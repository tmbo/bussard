//! `knx_add_device` (issue #749): add a new device from chat, the flow
//! `bussard adopt` runs at the terminal, on the same functions
//! ([`bussard_service::assign`] and [`bussard_service::adopt::flow`]).
//!
//! Three steps, one job of the server's job table
//! ([`crate::jobs::JobKind::Add`]):
//!
//! 1. **`press_button`.** The first call claims the job and answers at once
//!    with the question for the human ("press the programming button"). The
//!    job waits for the programming-mode broadcast as long as the CLI does
//!    ([`bussard_service::assign::PROGRAMMING_WAIT_TOTAL`]).
//! 2. **`identified`.** The device answered: the job reads what it is at its
//!    current address (mask, serial, manufacturer, order number), decides the
//!    target address, looks the product data up (the store, else the index:
//!    a download), and pauses with the plan sentences, a `plan_digest` and
//!    the question. Nothing is written; the slot is free while it waits.
//! 3. **`done`.** The write call presents the job, the digest and `yes: true`,
//!    plus `download: true` when the product data needs a download (the
//!    separate consent of `--yes-download`). The job re-reads the device and
//!    refuses when the digest no longer matches, downloads, writes the
//!    address, reads the device back independently at the new address
//!    (verified only when it answers there with the identified serial and
//!    mask), and writes the device file and its lock entry. A device the
//!    keyring lists is adopted where ETS put it, over `A_SecureData`; its
//!    Secure activation stays with ETS.

use std::time::Instant;

use bussard_model::history::SnapshotReason;
use bussard_model::{IndividualAddress, Model};
use bussard_service::BusService;
use bussard_service::adopt::flow::{
    ProductPlan, SelectedProduct, adopt_target, build_device, order_matches, product_plan,
    selected_from_archive, useful_objects,
};
use bussard_service::assign::{
    ProgrammingWait, Verified, VerifyKey, hex, identify, in_programming_mode, probe_occupant,
    still_in_programming_mode, verify_assignment_with, wait_for_programming_mode, write_address,
    write_device_file,
};
use bussard_service::identity::SecureStatus;
use bussard_service::secure::{SecureMaterial, ToolKeySource, ToolKeys};
use bussard_service::setup::{Collected, DownloadAnswer, DownloadPrompt, SetupError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{BussardMcp, ProgrammingTier, chain, put};

/// The question of the `press_button` step.
const PRESS_BUTTON: &str = "Press the programming button on the new device (its LED usually \
    lights up), then say done.";

/// One identified device waiting for the human's yes, by job id.
#[derive(Debug, Clone)]
pub(super) struct PendingAdd {
    /// The device's address when it answered the programming-mode broadcast.
    current: IndividualAddress,
    /// The address it gets.
    target: IndividualAddress,
    /// The `address` argument of the first call.
    address_arg: Option<String>,
    /// The `order_number` argument of the first call.
    order_arg: Option<String>,
    /// The archive the `product` argument of the first call stored.
    product_file: Option<std::path::PathBuf>,
    /// What the identification read.
    identified: Verified,
    /// The keyring lists the device: adopted where it is, over A_SecureData.
    secured: bool,
    /// The order number the product data is looked up by.
    order: Option<String>,
    /// Where the product data comes from.
    product: Option<ProductPlan>,
    /// The digest the human's yes answers.
    digest: String,
    /// When the device was identified.
    created: Instant,
}

/// What the identification established, before the digest.
struct Identification {
    /// The address it answered at.
    current: IndividualAddress,
    /// The address it gets.
    target: IndividualAddress,
    /// What it reported.
    identified: Verified,
    /// The keyring lists it.
    secured: bool,
    /// The order number for the product data.
    order: Option<String>,
    /// Where the product data comes from.
    product: Option<ProductPlan>,
    /// The product data is the file the `product` argument named.
    from_file: bool,
}

/// The plan digest: the device (current and target address, serial, mask,
/// manufacturer, order number, Secure), the product data it would get and the
/// model's device list.
fn add_digest(id: &Identification, model: &Model) -> String {
    let mut h = Sha256::new();
    put(&mut h, b"bussard-add-device-v1");
    put(&mut h, &id.current.raw().to_be_bytes());
    put(&mut h, &id.target.raw().to_be_bytes());
    put(&mut h, id.identified.serial.as_deref().unwrap_or_default());
    put(&mut h, &id.identified.mask.unwrap_or(0).to_be_bytes());
    put(
        &mut h,
        &id.identified.manufacturer_id.unwrap_or(0).to_be_bytes(),
    );
    put(
        &mut h,
        id.identified.order.as_deref().unwrap_or("").as_bytes(),
    );
    put(&mut h, id.identified.secure.as_str().as_bytes());
    put(&mut h, &[u8::from(id.secured)]);
    put(&mut h, id.order.as_deref().unwrap_or("").as_bytes());
    let product = match &id.product {
        Some(ProductPlan::Cached { path }) => format!("cached:{}", path.display()),
        Some(ProductPlan::Download { entry }) => format!("download:{}", entry.sha256),
        Some(ProductPlan::Missing { .. }) | None => "none".to_string(),
    };
    put(&mut h, product.as_bytes());
    for address in model.devices.keys() {
        put(&mut h, &address.raw().to_be_bytes());
    }
    let bytes: [u8; 32] = h.finalize().into();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Answers the download question with the human's `download: true`.
struct Consented;

impl DownloadPrompt for Consented {
    fn download(&mut self, _question: &str, _files: usize) -> Result<DownloadAnswer, SetupError> {
        Ok(DownloadAnswer::Yes)
    }
}

/// Who the device is, in words: the product name or order number, then the
/// manufacturer.
fn who(identified: &Verified) -> String {
    let manufacturer = identified
        .manufacturer_id
        .map(bussard_mgmt::manufacturers::display);
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

impl BussardMcp {
    /// `knx_add_device`'s body; `Err` is a refusal reason.
    pub(super) async fn add_device_tool(
        &self,
        args: super::AddDeviceArgs,
    ) -> Result<Value, String> {
        let (tier, _, gateway) = self.programming_preflight()?;
        match args.job.as_deref().map(str::trim) {
            None => {
                if args.plan_digest.is_some() || args.yes == Some(true) {
                    return Err(
                        "plan_digest and yes answer an identified device: pass the `job` \
                         knx_add_device returned with them"
                            .into(),
                    );
                }
                if let Some(address) = args.address.as_deref() {
                    bussard_service::assign::validate_explicit_address(
                        address,
                        Some(&self.state().model.reload()),
                    )
                    .map_err(|e| e.to_string())?;
                }
                let job = tier.jobs.claim_add()?;
                // `product`: the import `bussard adopt --product` runs, before
                // the bus is touched (issue #779).
                let imported = match args.product.as_deref().map(str::trim) {
                    Some(file) => match self.import_add_product(file).await {
                        Ok(imported) => Some(imported),
                        Err(reason) => {
                            tier.jobs.abandon(&job);
                            return Err(reason);
                        }
                    },
                    None => None,
                };
                let (product_file, product_import) = match imported {
                    Some((archive, sentences)) => (archive, Some(sentences)),
                    None => (None, None),
                };
                let me = self.clone();
                let (id, address, order) = (job.clone(), args.address, args.order_number);
                let worker = tokio::spawn(async move {
                    me.add_identify_job(&id, address, order, product_file).await;
                });
                self.watch_job(job.clone(), "add-device", worker);
                Ok(json!({
                    "ok": true,
                    "started": true,
                    "done": false,
                    "step": "press_button",
                    "job": job,
                    "gateway": gateway,
                    "product_import": product_import,
                    "question": PRESS_BUTTON,
                    "next_step": format!(
                        "Relay `question` to the human word for word. The server waits up to \
                         30 s for the device's programming-mode answer; call knx_job_status \
                         with job {job} every few seconds. When its step is `identified`, show \
                         the human its `sentences` and ask its `question`. Nothing is written \
                         before that."
                    ),
                }))
            }
            Some(job) => {
                let job = job.to_string();
                self.add_write_call(
                    tier,
                    &job,
                    args.plan_digest.as_deref(),
                    args.yes,
                    args.download,
                )
                .await
            }
        }
    }

    /// The first job: the wait for the button and the identification. Ends
    /// paused at `identified` (the slot free) or finished with the reason.
    async fn add_identify_job(
        &self,
        job: &str,
        address: Option<String>,
        order_arg: Option<String>,
        product_file: Option<std::path::PathBuf>,
    ) {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            return;
        };
        let outcome = {
            let _guard = tier.bus_lock.lock().await;
            let mut warm = self.warm().lock().await;
            warm.release().await;
            tier.jobs.step(job, "press_button");
            tier.jobs.ask(job, Some(PRESS_BUTTON.to_string()));
            self.add_identify(
                job,
                address.as_deref(),
                order_arg.as_deref(),
                product_file.as_deref(),
            )
            .await
        };
        match outcome {
            Ok((id, digest)) => {
                let target = id.target;
                let model = state.model.reload();
                let detail = identified_detail(&id, &model, &digest, tier);
                let question = add_question(&id);
                tier.adds().insert(
                    job.to_string(),
                    PendingAdd {
                        current: id.current,
                        target: id.target,
                        address_arg: address,
                        order_arg,
                        product_file,
                        identified: id.identified,
                        secured: id.secured,
                        order: id.order,
                        product: id.product,
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
    async fn add_identify(
        &self,
        job: &str,
        address: Option<&str>,
        order_arg: Option<&str>,
        product_file: Option<&std::path::Path>,
    ) -> Result<(Identification, String), String> {
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
        let found = wait_for_programming_mode(&service, source, &mut |_| {})
            .await
            .map_err(|e| chain(&e))?;
        let current = match found {
            ProgrammingWait::One(current) => current,
            ProgrammingWait::Several(found) => {
                let list: Vec<String> = found.iter().map(ToString::to_string).collect();
                return Err(format!(
                    "{} devices are in programming mode ({}); adding works on one device at a \
                     time. Ask the human to leave programming mode on all but the new one, then \
                     call knx_add_device again. Nothing was written.",
                    found.len(),
                    list.join(", ")
                ));
            }
            ProgrammingWait::Nothing { waited } => {
                return Err(format!(
                    "No device entered programming mode within {} s. Ask the human to press the \
                     programming button on the new device (its LED usually lights up), then call \
                     knx_add_device again. Nothing was written.",
                    waited.as_secs()
                ));
            }
        };
        tier.jobs.ask(job, None);
        tier.jobs
            .step(job, format!("identifying the device at {current}"));
        let id = self
            .identification(&service, source, current, address, order_arg, product_file)
            .await?;
        let digest = add_digest(&id, &state.model.reload());
        Ok((id, digest))
    }

    /// Reads what the device in programming mode at `current` is and plans
    /// its adoption: the target address, the occupant check, the product
    /// data (the archive `product_file` names when given). Read-only.
    async fn identification(
        &self,
        service: &BusService,
        source: IndividualAddress,
        current: IndividualAddress,
        address: Option<&str>,
        order_arg: Option<&str>,
        product_file: Option<&std::path::Path>,
    ) -> Result<Identification, String> {
        let state = self.state();
        let keyring = state.keyring.as_deref();
        let keys = ToolKeys::load(ToolKeySource {
            keyring,
            tool_key: None,
        })
        .map_err(|e| chain(&e))?;
        let secured = keys.lists(current);
        let key = if secured {
            keys.tool_key(current)
        } else {
            None
        };
        let identified = identify(service, source, current, key).await.map_err(|e| {
            format!(
                "the device in programming mode at {current} did not answer the \
                     identification ({}). Nothing was written.",
                chain(&e)
            )
        })?;
        if identified.secure == SecureStatus::ActivatedNoKey {
            return Err(bussard_service::adopt::flow::activated_without_key(
                current, current, &keys, keyring,
            ));
        }
        let model = state.model.reload();
        let target = adopt_target(address, current, secured, Some(&model)).map_err(|e| {
            let reason = e.to_string();
            if reason.ends_with("Nothing was written.") {
                reason
            } else {
                format!("{reason}. Nothing was written.")
            }
        })?;
        if target != current
            && let Some(occupant) = probe_occupant(service, source, target).await
        {
            return Err(format!(
                "{target} is already in use: a device answers there ({}). Two devices on one \
                 address answer the same connection. Pick a free address (the `address` \
                 argument) or re-address that device first. Nothing was written.",
                occupant.describe()
            ));
        }
        let order = order_arg
            .map(str::to_string)
            .or_else(|| identified.order.clone());
        let product = match product_file {
            Some(path) => Some(ProductPlan::Cached {
                path: path.to_path_buf(),
            }),
            None => order.as_deref().map(|o| product_plan(&state.dir, o)),
        };
        Ok(Identification {
            current,
            target,
            identified,
            secured,
            order,
            product,
            from_file: product_file.is_some(),
        })
    }

    /// The write call: checks the answer, takes the job up again and runs
    /// the write; answers with the result when it ends within the reply
    /// wait, else with the job.
    async fn add_write_call(
        &self,
        tier: &ProgrammingTier,
        job: &str,
        digest: Option<&str>,
        yes: Option<bool>,
        download: Option<bool>,
    ) -> Result<Value, String> {
        let began = Instant::now();
        let pending = {
            let mut adds = tier.adds();
            adds.retain(|_, p| p.created.elapsed() <= tier.plan_ttl);
            adds.get(job).cloned()
        };
        let Some(pending) = pending else {
            return Err(format!(
                "no identified device waits under job {job} (it was written, refused, or older \
                 than the plan lifetime). Call knx_add_device without `job` to start again."
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
                "adding the device writes to the bus: pass yes: true only after the human's \
                 explicit yes to the question. Nothing was written."
                    .into(),
            );
        }
        if matches!(pending.product, Some(ProductPlan::Download { .. })) && download != Some(true) {
            return Err(
                "the product data needs a download from the vendor, a separate consent: ask the \
                 human whether bussard may download it, and pass download: true only after a \
                 yes to that too (without it, nothing is written)."
                    .into(),
            );
        }
        tier.jobs.resume(job, "checking the device again")?;
        tier.adds().remove(job);
        let me = self.clone();
        let id = job.to_string();
        let worker = tokio::spawn(async move {
            let result = me.add_write_job(&id, pending).await;
            if let Some(tier) = me.state().programming.as_ref() {
                tier.jobs.finish(&id, result);
            }
        });
        self.watch_job(job.to_string(), "add-device", worker);
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
                "The device is being added in the server as job {job}. Call knx_job_status \
                 with job {job} every few seconds until `done` is true; its `result` is the \
                 outcome."
            ),
        }))
    }

    /// The write job: the fresh read, the download, the address, the
    /// read-back, the device file. Returns the job's result.
    async fn add_write_job(&self, job: &str, pending: PendingAdd) -> Value {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            return json!({ "ok": false, "reason": "the programming tier is off" });
        };
        let _guard = tier.bus_lock.lock().await;
        let mut warm = self.warm().lock().await;
        warm.release().await;
        let result = self.add_write(job, &pending).await;
        drop(warm);
        match result {
            Ok(value) => value,
            Err(reason) => json!({
                "ok": false,
                "verified": false,
                "reason": reason,
            }),
        }
    }

    /// The write itself; `Err` is the reason it stopped.
    async fn add_write(&self, job: &str, p: &PendingAdd) -> Result<Value, String> {
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

        // The fresh read: the same single device in programming mode, the same
        // identity and plan, else the digest the human answered is stale.
        let now = in_programming_mode(&service, source)
            .await
            .map_err(|e| chain(&e))?;
        if now != [p.current] {
            return Err(format!(
                "the device is no longer the one device in programming mode at {} (now: {}). \
                 Ask the human to press its programming button again, then call knx_add_device \
                 again. Nothing was written.",
                p.current,
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
        let fresh = self
            .identification(
                &service,
                source,
                p.current,
                p.address_arg.as_deref(),
                p.order_arg.as_deref(),
                p.product_file.as_deref(),
            )
            .await?;
        if add_digest(&fresh, &state.model.reload()) != p.digest {
            return Err(
                "a fresh read no longer produces the plan the human answered (the device, its \
                 product data or the model changed). Call knx_add_device again for a new plan. \
                 Nothing was written."
                    .into(),
            );
        }

        let mut notes: Vec<String> = Vec::new();
        // The product data: the store, or the download the human agreed to.
        let selected = match (&p.order, &p.product) {
            // A `product` file is used whatever order number the device
            // reported, as `bussard adopt --product` uses it.
            (order, Some(ProductPlan::Cached { path }))
                if order.is_some() || p.product_file.is_some() =>
            {
                let order = order.as_deref().unwrap_or_default();
                match selected_from_archive(path, &dir, order) {
                    Ok(selected) => Some(selected),
                    Err(why) => {
                        notes.push(format!(
                            "The product data {} did not load ({why}); the device was added \
                             without a com-object table.",
                            if order.is_empty() {
                                format!("in {}", path.display())
                            } else {
                                format!("for {order}")
                            }
                        ));
                        None
                    }
                }
            }
            (Some(order), Some(ProductPlan::Download { entry })) => {
                tier.jobs.step(
                    job,
                    format!("downloading the product data for {order} ({})", entry.name),
                );
                self.download_product(&dir, order, &mut notes)
            }
            (Some(_), Some(ProductPlan::Missing { sentence })) => {
                notes.push(sentence.clone());
                None
            }
            _ => None,
        };

        // The address.
        let model = state.model.reload();
        if p.target != p.current {
            if let Some(occupant) = probe_occupant(&service, source, p.target).await {
                return Err(format!(
                    "{} is already in use: a device answers there ({}). Nothing was written.",
                    p.target,
                    occupant.describe()
                ));
            }
            tier.jobs
                .step(job, format!("writing the address {}", p.target));
            write_address(&service, source, p.target)
                .await
                .map_err(|e| format!("broadcasting the new individual address: {}", chain(&e)))?;
        }

        // The independent read-back at the target.
        tier.jobs
            .step(job, format!("reading the device back at {}", p.target));
        let material = self.add_material(p)?;
        let key = VerifyKey {
            tool_key: material.tool_key.clone(),
            from_old_address: false,
        };
        let verified = verify_assignment_with(&service, source, p.target, false, &key)
            .await
            .map_err(|e| chain(&e))?;
        notes.extend(verified.warnings.iter().cloned());
        if verified.secure == SecureStatus::ActivatedNoKey {
            let keys = ToolKeys::load(ToolKeySource {
                keyring: state.keyring.as_deref(),
                tool_key: None,
            })
            .map_err(|e| chain(&e))?;
            return Err(bussard_service::adopt::flow::activated_without_key(
                p.target,
                p.current,
                &keys,
                state.keyring.as_deref(),
            ));
        }
        let serial_matches = match (&verified.serial, &p.identified.serial) {
            (Some(now), Some(then)) => now == then,
            _ => true,
        };
        let mask_matches = match (verified.mask, p.identified.mask) {
            (Some(now), Some(then)) => now == then,
            _ => true,
        };
        let readback_verified = serial_matches && mask_matches;
        if p.target != p.current {
            if still_in_programming_mode(&service, source, p.target).await {
                notes.push(format!(
                    "{} is still in programming mode after the assignment; ask the human to \
                     press its programming button once to leave it (on KNX Virtual: toggle it \
                     off in the GUI).",
                    p.target
                ));
            }
        } else {
            notes.push(format!(
                "{} stays in programming mode (nothing was written to it); ask the human to \
                 press its programming button to leave it.",
                p.target
            ));
        }
        let mismatch = match (&selected, verified.order.as_deref()) {
            (Some(sel), Some(read)) if !sel.order_numbers.is_empty() => {
                !order_matches(read, &sel.order_numbers)
            }
            _ => false,
        };
        if mismatch && let Some(sel) = &selected {
            notes.push(format!(
                "The device reported order number {:?}, which is not among the product's order \
                 numbers ({}): the product data may not match this hardware.",
                verified.order.as_deref().unwrap_or_default(),
                sel.order_numbers.join(", ")
            ));
        }

        // The device file.
        tier.jobs.step(job, "writing the device file");
        let device = build_device(p.target, &verified, selected.as_ref());
        let (device, model_out, secure) = if verified.secure == SecureStatus::Activated {
            let (device, model_out, summary) = self
                .add_secured(
                    &service,
                    source,
                    p,
                    &model,
                    device,
                    selected.as_ref(),
                    &material,
                )
                .await?;
            (device, Some(model_out), Some(summary))
        } else {
            (device, None, None)
        };
        let mut device = device;
        if device.knxnet.is_none()
            && let Ok(Some(knxnet)) = bussard_service::adopt::flow::read_knxnet_settings(
                &service, source, p.target, &dir, &material,
            )
            .await
        {
            device.knxnet = Some(knxnet.as_config());
        }
        let mut said = Collected::default();
        bussard_service::setup::import::snapshot(
            &dir,
            SnapshotReason::new("knx_add_device")
                .with_args([p.target.to_string()])
                .with_result("before writing the added device file"),
            &mut said,
        );
        let path = write_device_file(
            model_out.as_ref().or(Some(&model)),
            &dir,
            device.clone(),
            verified.serial.as_deref(),
            "device file",
        )
        .map_err(|e| chain(&e))?;
        attach_serial(&dir, p.target, verified.serial.as_deref(), &mut notes);
        let _ = state.model.reload();

        Ok(done_result(DoneParts {
            p,
            verified: &verified,
            readback_verified,
            device: &device,
            selected: selected.as_ref(),
            path: &path,
            dir: &dir,
            secure,
            notes,
        }))
    }

    /// The Data Secure material for the device: its tool key and the
    /// keyring's group keys when the keyring lists it, else nothing.
    fn add_material(&self, p: &PendingAdd) -> Result<SecureMaterial, String> {
        if !p.secured {
            return Ok(SecureMaterial::default());
        }
        let keys = ToolKeys::load(ToolKeySource {
            keyring: self.state().keyring.as_deref(),
            tool_key: None,
        })
        .map_err(|e| chain(&e))?;
        keys.material(p.current, true).map_err(|e| chain(&e))
    }

    /// The `product` argument: imports the `.knxprod` into the product store
    /// as `bussard adopt --product` does, through the function
    /// `bussard import-product` and `knx_import_file` call, behind a history
    /// snapshot. Returns the stored archive and the import's sentences.
    async fn import_add_product(
        &self,
        file: &str,
    ) -> Result<(Option<std::path::PathBuf>, Vec<String>), String> {
        let path = std::path::PathBuf::from(file);
        let is_knxprod = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("knxprod"));
        if !is_knxprod {
            return Err(format!(
                "product must be a vendor .knxprod file, not {file}; an ETS project export goes \
                 through knx_import_file first. Nothing was written."
            ));
        }
        let dir = self.state().dir.clone();
        let imported = tokio::task::spawn_blocking(move || import_product(&dir, &path))
            .await
            .map_err(|e| format!("the product import did not finish: {e}"))?;
        // Whatever the import wrote, the server reads the files afresh.
        self.state().model.reload();
        imported.map_err(|why| {
            format!("the product file {file} did not import ({why}). Nothing was written.")
        })
    }

    /// Downloads the product data for `order` (the human agreed) and loads
    /// it; a failure is a note and the device is added without it.
    fn download_product(
        &self,
        dir: &std::path::Path,
        order: &str,
        notes: &mut Vec<String>,
    ) -> Option<SelectedProduct> {
        let mut said = Collected::default();
        let outcome = match bussard_service::setup::products::fetch_missing(
            dir,
            &[order.to_string()],
            &mut Consented,
            &mut said,
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                notes.push(format!(
                    "The product data for {order} was not downloaded ({}); the device was added \
                     without a com-object table.",
                    chain(&err)
                ));
                return None;
            }
        };
        let Some((_, path)) = outcome.fetched.first() else {
            let why = outcome
                .not_fetched
                .first()
                .map(|(_, why)| why.clone())
                .unwrap_or_else(|| "it is not in the index".to_string());
            notes.push(format!(
                "The product data for {order} was not downloaded ({why}); the device was added \
                 without a com-object table."
            ));
            return None;
        };
        match selected_from_archive(path, dir, order) {
            Ok(selected) => Some(selected),
            Err(why) => {
                notes.push(format!(
                    "The downloaded product data for {order} did not load ({why}); the device \
                     was added without a com-object table."
                ));
                None
            }
        }
    }

    /// The secured half of a Data Secure device: what ETS programmed into
    /// it, read over A_SecureData and recorded.
    #[allow(clippy::too_many_arguments)] // one call site; the flow's state
    async fn add_secured(
        &self,
        service: &BusService,
        source: IndividualAddress,
        p: &PendingAdd,
        model: &Model,
        device: bussard_model::schema::Device,
        selected: Option<&SelectedProduct>,
        material: &SecureMaterial,
    ) -> Result<
        (
            bussard_model::schema::Device,
            Model,
            bussard_service::adopt::flow::SecureSummary,
        ),
        String,
    > {
        let dir = &self.state().dir;
        let with_device = bussard_service::adopt::flow::with_device(Some(model), &device, p.target);
        let mut notes = Vec::new();
        let lookup = bussard_service::params::resolve_product(
            dir,
            bussard_service::params::Selection {
                product: None,
                application: selected.map(|s| s.application_ref.as_str()),
            },
            Some(&with_device),
            p.target,
            bussard_service::params::MissingProduct::Warn,
            None,
        );
        let product = match lookup {
            Ok(lookup) => {
                if let Some(warning) = lookup.warning {
                    notes.push(format!("parameters not read: {warning}"));
                }
                lookup.source
            }
            Err(err) => {
                notes.push(format!("parameters not read: {}", chain(&err)));
                None
            }
        };
        let read = bussard_service::adopt::flow::read_secured(
            service,
            source,
            p.target,
            &with_device,
            product.as_ref(),
            material,
            notes,
        )
        .await
        .map_err(|e| {
            format!(
                "reading {} over A_SecureData with its keyring tool key: {}",
                p.target,
                chain(&e)
            )
        })?;
        bussard_service::adopt::flow::record_secured(
            Some(model),
            device,
            p.target,
            selected,
            &read,
            material,
            p.current,
        )
        .map_err(|e| chain(&e))
    }
}

/// Moves a certificate entered before the device had an address to it
/// (issue #728), when the key store and its password are there.
fn attach_serial(
    dir: &std::path::Path,
    target: IndividualAddress,
    serial: Option<&[u8]>,
    notes: &mut Vec<String>,
) {
    use bussard_project::keystore::{AttachOutcome, KeyStore, SerialNumber};
    let Some(serial) = serial.and_then(|s| <[u8; 6]>::try_from(s).ok()) else {
        return;
    };
    if !KeyStore::path(dir).exists() {
        return;
    }
    let Ok(password) = bussard_model::dotenv::var(bussard_service::secure::KEYRING_PASSWORD_ENV)
    else {
        return;
    };
    match bussard_service::attach_serials(dir, &password, &[(target, SerialNumber(serial))]) {
        Ok(outcomes) => {
            if outcomes
                .iter()
                .any(|(_, _, outcome)| matches!(outcome, AttachOutcome::Attached))
            {
                notes.push(format!(
                    "The device certificate entered for serial {} now belongs to {target}.",
                    hex(&serial)
                ));
            }
        }
        Err(err) => notes.push(format!("Certificates were not attached to {target}: {err}")),
    }
}

/// The question of the `identified` step.
fn add_question(id: &Identification) -> String {
    let address = if id.target == id.current {
        format!("Adopt it at {}", id.current)
    } else {
        format!("Assign {}", id.target)
    };
    let product = match &id.product {
        Some(ProductPlan::Download { .. }) => ", download the product data",
        _ => "",
    };
    format!("{address}{product} and write its device file? Say yes.")
}

/// The fields the `identified` step reports at the top of the job status.
fn identified_detail(
    id: &Identification,
    model: &Model,
    digest: &str,
    tier: &ProgrammingTier,
) -> Value {
    let v = &id.identified;
    let mask = v.mask.map(|m| format!("{m:04X}"));
    let system = v.mask.map(bussard_mgmt::system_type);
    let mut sentences = vec![format!(
        "{} is in programming mode at {}{}{}.",
        who(v),
        id.current,
        v.serial
            .as_deref()
            .map(|s| format!(", serial {}", hex(s)))
            .unwrap_or_default(),
        match (&mask, system) {
            (Some(mask), Some(system)) => format!(", mask {mask} ({system})"),
            _ => String::new(),
        }
    )];
    if id.secured {
        sentences.push(format!(
            "It is KNX Data Secure-activated and the keyring lists it at {}: it keeps that \
             address and bussard reads what ETS programmed into it over A_SecureData. Nothing \
             is written to it.",
            id.current
        ));
    } else if id.target == id.current {
        sentences.push(format!(
            "It already has the address {}; no address is written.",
            id.target
        ));
    } else {
        sentences.push(format!(
            "It gets the address {} (the device file names it there).",
            id.target
        ));
    }
    let (product_data, download_needed) = match (&id.order, &id.product) {
        (_, Some(ProductPlan::Cached { path })) if id.from_file => (
            format!(
                "the file you gave, imported into the model's product store ({})",
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            false,
        ),
        (Some(order), Some(ProductPlan::Cached { path })) => (
            format!(
                "{order}: in the model's product store ({})",
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            false,
        ),
        (Some(order), Some(ProductPlan::Download { entry })) => (
            format!(
                "would download {} ({}, order number {order}) from the vendor index ({:.1} MB, \
                 {})",
                entry.name,
                entry.manufacturer,
                entry.size as f64 / 1_000_000.0,
                entry.url
            ),
            true,
        ),
        (Some(_), Some(ProductPlan::Missing { sentence })) => (
            format!("none: {sentence} The device is added without a com-object table."),
            false,
        ),
        _ => (
            "none: the device reported no order number; it is added without a com-object table."
                .to_string(),
            false,
        ),
    };
    sentences.push(format!("Product data: {product_data}."));
    if download_needed {
        sentences.push(
            "The download is copyrighted vendor data stored under products/; it needs the \
             human's own yes (download: true)."
                .to_string(),
        );
    }
    sentences.push(format!(
        "Then bussard reads the device back at {} and writes devices/{}.toml with its \
         bussard.lock entry.",
        id.target, id.target
    ));
    let now = std::time::SystemTime::now();
    json!({
        "current_address": id.current.to_string(),
        "serial": v.serial.as_deref().map(hex),
        "mask": mask,
        "system_type": system,
        "manufacturer": v.manufacturer_id.map(bussard_mgmt::manufacturers::display),
        "order_number": v.order,
        "secure": v.secure.as_str(),
        "keeps_address": id.target == id.current,
        "product_data": product_data,
        "download_needed": download_needed,
        "sentences": sentences,
        "plan_digest": digest,
        "model_devices": model.devices.len(),
        "expires_at": bussard_monitor::timefmt::to_rfc3339(now + tier.plan_ttl),
    })
}

/// What the `done` result is made of.
struct DoneParts<'a> {
    /// The plan the human answered.
    p: &'a PendingAdd,
    /// The read-back at the target.
    verified: &'a Verified,
    /// The read-back matched the identification (serial and mask).
    readback_verified: bool,
    /// The device file written.
    device: &'a bussard_model::schema::Device,
    /// The product data it got.
    selected: Option<&'a SelectedProduct>,
    /// The device file's path.
    path: &'a std::path::Path,
    /// The model directory.
    dir: &'a std::path::Path,
    /// What a Data Secure adoption recorded.
    secure: Option<bussard_service::adopt::flow::SecureSummary>,
    /// Notes for the human.
    notes: Vec<String>,
}

/// The `done` result: names first, one summary sentence.
fn done_result(d: DoneParts<'_>) -> Value {
    let DoneParts {
        p,
        verified,
        readback_verified,
        device,
        selected,
        path,
        dir,
        secure,
        notes,
    } = d;
    let name = device.name.clone();
    let relative = path.strip_prefix(dir).unwrap_or(path).display().to_string();
    let assigned = p.target != p.current;
    let product = selected.map(|s| {
        json!({
            "name": s.display_name(),
            "application": s.application_ref,
            "com_objects": s.com_objects.len(),
        })
    });
    let objects: Vec<Value> = useful_objects(device, selected)
        .into_iter()
        .take(8)
        .map(|o| {
            json!({
                "object": o.number,
                "text": o.text,
                "dpt": o.dpt.map(|d| d.to_string()),
                "flags": o.flags.to_string(),
                "table": o.table,
                "key": o.key,
            })
        })
        .collect();
    let what = if assigned {
        format!("now answers at {} (was {})", p.target, p.current)
    } else {
        format!("answers at {}", p.target)
    };
    let check = if readback_verified {
        "the read-back there matches the identified serial and mask"
    } else {
        "but the read-back there does NOT match the identified serial or mask"
    };
    let summary = format!(
        "{name} ({}) {what}; {check}; its device file is {relative}.",
        p.target
    );
    let next_step = match (&secure, selected) {
        (Some(_), _) => format!(
            "Tell the human the summary. Its links and parameters are in the model now; \
             knx_plan_device for {} should report nothing to do.",
            p.target
        ),
        (None, Some(_)) => format!(
            "Tell the human the summary, then name the device and its room \
             (knx_rename_device or the device file) and wire its group objects: `objects` lists \
             them, transmit-capable first. knx_plan_device and knx_apply_device for {} write \
             the links; a factory-fresh device needs its application loaded first (the plan \
             says so).",
            p.target
        ),
        (None, None) => format!(
            "Tell the human the summary. It has no product data yet: knx_import_file with its \
             .knxprod attaches it; then wire its group objects and plan {}.",
            p.target
        ),
    };
    json!({
        "ok": readback_verified,
        "step": "done",
        "name": name,
        "address": p.target.to_string(),
        "from": p.current.to_string(),
        "assigned": assigned,
        "verified": readback_verified,
        "readback": {
            "mask": verified.mask.map(|m| format!("{m:04X}")),
            "serial": verified.serial.as_deref().map(hex),
            "order_number": verified.order,
            "secure": verified.secure.as_str(),
        },
        "device_file": relative,
        "product": product,
        "objects": objects,
        "secure": secure.map(|s| json!({
            "links": s.links,
            "parameters": s.parameters,
            "secure_objects": s.adoption.secure_objects,
            "secure_groups": s.adoption.secure_groups.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "notes": s.notes,
        })),
        "notes": notes,
        "summary": summary,
        "next_step": next_step,
    })
}

impl ProgrammingTier {
    /// The identified devices waiting for a yes, recovering from a poisoned
    /// lock.
    pub(super) fn adds(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, PendingAdd>> {
        self.adds
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Imports the `.knxprod` at `file` into the product store of `dir` behind a
/// history snapshot; `Err` is the reason in words.
fn import_product(
    dir: &std::path::Path,
    file: &std::path::Path,
) -> Result<(Option<std::path::PathBuf>, Vec<String>), String> {
    let mut out = Collected::default();
    bussard_service::setup::import::snapshot(
        dir,
        SnapshotReason::new("mcp knx_add_device")
            .with_args(["product".to_string(), file.display().to_string()])
            .with_result("before importing the product data"),
        &mut out,
    );
    let imported = bussard_service::files::products::import_product_file(file, dir, None, &mut out)
        .map_err(|err| bussard_service::setup::products::error_chain(&err))?;
    let mut sentences = vec![imported.stored];
    if !imported.models.is_empty() {
        sentences.push(format!(
            "Generated {} product model(s): {}",
            imported.models.len(),
            imported.models.join(", ")
        ));
    }
    Ok((imported.archive, sentences))
}
