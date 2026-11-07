//! `knx_add_device` (issue #749): add a new device from chat, the flow
//! `bussard adopt` runs at the terminal, on the same functions
//! ([`bussard_service::program::adopt`], issue #902).
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

use crate::jobs::{JobKind, JobSink, Subject};
use bussard_model::history::SnapshotReason;
use bussard_model::{IndividualAddress, Model};
use bussard_service::adopt::flow::{
    ProductPlan, SelectedProduct, product_plan, selected_from_archive, useful_objects,
};
use bussard_service::assign::{AssignError, hex};
use bussard_service::observer::Collected;
use bussard_service::program::Question;
use bussard_service::program::adopt::{self, Adopted, Keys, PlanRequest, Planned, RunRequest};
use bussard_service::program::assign::{AssignFlow, Stop};
use bussard_service::program::plan::Fingerprint;
use bussard_service::secure::{ToolKeySource, ToolKeys};
use serde_json::{Value, json};

use super::addressing::{Wording, Yes, assigned_notes, found_sentence, readback_json, refused};
use super::{BussardMcp, ProgrammingTier, chain};

/// The question of the `press_button` step.
const PRESS_BUTTON: &str = "Press the programming button on the new device (its LED usually \
    lights up), then say done.";

/// How `knx_add_device` names the device in its refusals.
const WORDING: Wording = Wording {
    work: "adding",
    device: "the new device",
    all_but: "the new one",
    subject: "the device",
    tool: "knx_add_device",
};

/// What the identification established: the plan of the adoption and where
/// its product data comes from.
#[derive(Debug, Clone)]
struct Identification {
    /// The adoption's plan (the identified device, its address).
    planned: Planned,
    /// The order number the product data is looked up by.
    order: Option<String>,
    /// Where the product data comes from.
    product: Option<ProductPlan>,
    /// The product data is the file the `product` argument named.
    from_file: bool,
}

impl Identification {
    /// What the device reported.
    fn identified(&self) -> bussard_service::assign::Verified {
        self.planned.identified.clone().unwrap_or_default()
    }
}

/// One identified device waiting for the human's yes, by job id.
#[derive(Debug, Clone)]
pub(super) struct AddPlan {
    /// What the identification established.
    id: Identification,
    /// The `address` argument of the first call.
    address_arg: Option<String>,
    /// The `order_number` argument of the first call.
    order_arg: Option<String>,
    /// The archive the `product` argument of the first call stored.
    product_file: Option<std::path::PathBuf>,
    /// The digest the human's yes answers.
    digest: String,
}

/// The plan digest: the device (current and target address, serial, mask,
/// manufacturer, order number, Secure), the product data it would get and the
/// model's device list.
fn add_digest(id: &Identification, model: &Model) -> String {
    let (p, v) = (&id.planned, id.identified());
    let product = match &id.product {
        Some(ProductPlan::Cached { path }) => format!("cached:{}", path.display()),
        Some(ProductPlan::Download { entry }) => format!("download:{}", entry.sha256),
        Some(ProductPlan::Missing { .. }) | None => "none".to_string(),
    };
    let h = Fingerprint::new(b"bussard-add-device-v1")
        .address(p.current)
        .address(p.target)
        .put(v.serial.as_deref().unwrap_or_default())
        .put(v.mask.unwrap_or(0).to_be_bytes())
        .put(v.manufacturer_id.unwrap_or(0).to_be_bytes())
        .put(v.order.as_deref().unwrap_or(""))
        .put(v.secure.as_str())
        .put([u8::from(p.secured)])
        .put(id.order.as_deref().unwrap_or(""))
        .put(product);
    let h = model
        .devices
        .keys()
        .fold(h, |h, address| h.address(*address));
    format!("sha256:{}", h.hex())
}

/// The refusal for a stop of the flow; `planning` while nothing is decided
/// yet (the occupied address gets the longer advice).
fn refusal(stop: Stop, planning: bool) -> String {
    if let Some(reason) = WORDING.wait_refusal(&stop) {
        return reason;
    }
    match stop {
        Stop::Identify { current, source } => format!(
            "the device in programming mode at {current} did not answer the identification \
             ({}). Nothing was written.",
            chain(&source)
        ),
        Stop::Occupied { target, occupant } if planning => format!(
            "{target} is already in use: a device answers there ({}). Two devices on one address \
             answer the same connection. Pick a free address (the `address` argument) or \
             re-address that device first. Nothing was written.",
            occupant.describe()
        ),
        Stop::Occupied { target, occupant } => format!(
            "{target} is already in use: a device answers there ({}). Nothing was written.",
            occupant.describe()
        ),
        Stop::Assign(AssignError::Refused(reason)) if reason.ends_with("Nothing was written.") => {
            reason
        }
        Stop::Assign(AssignError::Refused(reason)) => format!("{reason}. Nothing was written."),
        Stop::Refused(reason) => reason,
        other => chain(&other),
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
                let job = tier.jobs.claim(JobKind::Add, Subject::Bus)?.id;
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
                tier.jobs.watch(&job, "add-device", worker);
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
        let outcome = self
            .on_bus(tier, async {
                tier.jobs.step(job, "press_button");
                tier.jobs.ask(job, Some(PRESS_BUTTON.to_string()));
                self.add_identify(
                    job,
                    address.as_deref(),
                    order_arg.as_deref(),
                    product_file.as_deref(),
                )
                .await
            })
            .await;
        match outcome {
            Ok((id, digest)) => {
                let target = id.planned.target;
                let model = state.model.reload();
                let detail = identified_detail(&id, &model, &digest, tier);
                let question = add_question(&id);
                let plan = AddPlan {
                    id,
                    address_arg: address,
                    order_arg,
                    product_file,
                    digest,
                };
                tier.adds.insert(job, "", plan);
                tier.jobs
                    .pause(job, "identified", question, Some(target), detail);
            }
            Err(reason) => tier.jobs.finish(job, refused(reason)),
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
        let (service, source) = self.address_bus().await?;
        let flow = AssignFlow {
            service: &service,
            source,
        };
        let observer = &mut self.add_observer(tier, job);
        let current = flow
            .wait_for_one(observer)
            .await
            .map_err(|stop| refusal(stop, true))?;
        let id = self
            .identification(&flow, current, address, order_arg, product_file, observer)
            .await?;
        let digest = add_digest(&id, &state.model.reload());
        Ok((id, digest))
    }

    /// The observer of an add job.
    fn add_observer<'a>(&self, tier: &'a ProgrammingTier, job: &'a str) -> JobSink<'a> {
        JobSink::new(&tier.jobs, job).press(PRESS_BUTTON.to_string())
    }

    /// The keyring's tool keys.
    fn add_keys(&self) -> Result<ToolKeys, String> {
        ToolKeys::load(ToolKeySource {
            keyring: self.state().keyring.as_deref(),
            tool_key: None,
        })
        .map_err(|e| chain(&e))
    }

    /// Reads what the device in programming mode at `current` is and plans
    /// its adoption ([`adopt::plan`]) and its product data (the archive
    /// `product_file` names when given). Read-only.
    async fn identification(
        &self,
        flow: &AssignFlow<'_>,
        current: IndividualAddress,
        address: Option<&str>,
        order_arg: Option<&str>,
        product_file: Option<&std::path::Path>,
        observer: &mut JobSink<'_>,
    ) -> Result<Identification, String> {
        let state = self.state();
        let keys = self.add_keys()?;
        let model = state.model.reload();
        let request = PlanRequest {
            address,
            model: Some(&model),
            keys: Keys {
                keys: &keys,
                keyring: state.keyring.as_deref(),
            },
            identify: true,
            force: false,
        };
        let planned = adopt::plan(flow, current, request, observer)
            .await
            .map_err(|stop| refusal(stop, true))?;
        let order = order_arg
            .map(str::to_string)
            .or_else(|| planned.identified.as_ref().and_then(|v| v.order.clone()));
        let product = match product_file {
            Some(path) => Some(ProductPlan::Cached {
                path: path.to_path_buf(),
            }),
            None => order.as_deref().map(|o| product_plan(&state.dir, o)),
        };
        Ok(Identification {
            planned,
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
        let pending = tier.adds.get(job).ok_or_else(|| {
            format!(
                "no identified device waits under job {job} (it was written, refused, or older \
                 than the plan lifetime). Call knx_add_device without `job` to start again."
            )
        })?;
        let needs_download = matches!(pending.id.product, Some(ProductPlan::Download { .. }));
        Yes {
            job,
            digest,
            yes,
            download,
        }
        .check(&pending.digest, "adding the device", needs_download)?;
        tier.jobs.resume(job, "checking the device again")?;
        tier.adds.retire(job);
        let me = self.clone();
        let id = job.to_string();
        let work = async move { me.add_write_job(&id, pending).await };
        let next_step = format!(
            "The device is being added in the server as job {job}. Call knx_job_status with job \
             {job} every few seconds until `done` is true; its `result` is the outcome."
        );
        self.spawn_write(tier, job, began, "add-device", work, next_step)
            .await
    }

    /// The write job: the fresh read, the download, the address, the
    /// read-back, the device file. Returns the job's result.
    async fn add_write_job(&self, job: &str, pending: AddPlan) -> Value {
        let state = std::sync::Arc::clone(self.state());
        let Some(tier) = state.programming.as_ref() else {
            return json!({ "ok": false, "reason": "the programming tier is off" });
        };
        match self.on_bus(tier, self.add_write(job, &pending)).await {
            Ok(value) => value,
            Err(reason) => json!({
                "ok": false,
                "verified": false,
                "reason": reason,
            }),
        }
    }

    /// The write itself; `Err` is the reason it stopped.
    async fn add_write(&self, job: &str, p: &AddPlan) -> Result<Value, String> {
        let state = self.state();
        let tier = state
            .programming
            .as_ref()
            .ok_or("the programming tier is off")?;
        let dir = state.dir.clone();
        let (service, source) = self.address_bus().await?;
        let flow = AssignFlow {
            service: &service,
            source,
        };
        let observer = &mut self.add_observer(tier, job);

        // The fresh read: the same single device in programming mode, the same
        // identity and plan, else the digest the human answered is stale.
        let current = p.id.planned.current;
        flow.still_the_one(current)
            .await
            .map_err(|stop| refusal(stop, true))?;
        let fresh = self
            .identification(
                &flow,
                current,
                p.address_arg.as_deref(),
                p.order_arg.as_deref(),
                p.product_file.as_deref(),
                observer,
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

        let keys = self.add_keys()?;
        let model = state.model.reload();
        let mut notes: Vec<String> = Vec::new();
        let target = p.id.planned.target;
        let jobs = &tier.jobs;
        let mut product = |_: Option<&str>| select_product(&dir, p, jobs, job, &mut notes);
        let request = RunRequest {
            dir: &dir,
            model: Some(&model),
            keys: Keys {
                keys: &keys,
                keyring: state.keyring.as_deref(),
            },
            question: &Question {
                kind: bussard_service::observer::Ask::Write,
                prompt: add_question(&p.id),
                action: format!("knx_add_device job {job}"),
            },
            recheck_target: true,
            product: &mut product,
            product_file: None,
            on_parse: None,
            snapshot: SnapshotReason::new("knx_add_device")
                .with_args([target.to_string()])
                .with_result("before writing the added device file"),
        };
        let adopted = adopt::run(&flow, &p.id.planned, request, observer)
            .await
            .map_err(|stop| refusal(stop, false))?;
        notes.extend(assigned_notes(&adopted.assigned));
        if let (Some(read), Some(sel)) = (&adopted.order_mismatch, &adopted.selected) {
            notes.push(format!(
                "The device reported order number {read:?}, which is not among the product's \
                 order numbers ({}): the product data may not match this hardware.",
                sel.order_numbers.join(", ")
            ));
        }
        attach_serial(
            &dir,
            target,
            adopted.assigned.verified.serial.as_deref(),
            &mut notes,
        );
        let _ = state.model.reload();
        Ok(done_result(&adopted, &dir, notes))
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
}

/// The product data the human agreed to: the stored archive, or the
/// download (a failure is a note and the device is added without it).
fn select_product(
    dir: &std::path::Path,
    p: &AddPlan,
    jobs: &crate::jobs::JobTable,
    job: &str,
    notes: &mut Vec<String>,
) -> Option<SelectedProduct> {
    let without = "the device was added without a com-object table.";
    match (&p.id.order, &p.id.product) {
        // A `product` file is used whatever order number the device
        // reported, as `bussard adopt --product` uses it.
        (order, Some(ProductPlan::Cached { path }))
            if order.is_some() || p.product_file.is_some() =>
        {
            let order = order.as_deref().unwrap_or_default();
            selected_from_archive(path, dir, order)
                .map_err(|why| {
                    let what = if order.is_empty() {
                        format!("in {}", path.display())
                    } else {
                        format!("for {order}")
                    };
                    notes.push(format!(
                        "The product data {what} did not load ({why}); {without}"
                    ));
                })
                .ok()
        }
        (Some(order), Some(ProductPlan::Download { entry })) => {
            jobs.step(
                job,
                format!("downloading the product data for {order} ({})", entry.name),
            );
            let path = super::addressing::download(dir, order)
                .map_err(|why| {
                    notes.push(format!(
                        "The product data for {order} was not downloaded ({why}); {without}"
                    ));
                })
                .ok()?;
            selected_from_archive(&path, dir, order)
                .map_err(|why| {
                    notes.push(format!(
                        "The downloaded product data for {order} did not load ({why}); {without}"
                    ));
                })
                .ok()
        }
        (Some(_), Some(ProductPlan::Missing { sentence })) => {
            notes.push(sentence.clone());
            None
        }
        _ => None,
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
    let (current, target) = (id.planned.current, id.planned.target);
    let address = if target == current {
        format!("Adopt it at {current}")
    } else {
        format!("Assign {target}")
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
    let v = id.identified();
    let (current, target) = (id.planned.current, id.planned.target);
    let mut sentences = vec![found_sentence(&v, current, "")];
    sentences.push(if id.planned.secured {
        format!(
            "It is KNX Data Secure-activated and the keyring lists it at {current}: it keeps that \
             address and bussard reads what ETS programmed into it over A_SecureData. Nothing \
             is written to it."
        )
    } else if target == current {
        format!("It already has the address {target}; no address is written.")
    } else {
        format!("It gets the address {target} (the device file names it there).")
    });
    let file_name = |path: &std::path::Path| {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let (product_data, download_needed) = match (&id.order, &id.product) {
        (_, Some(ProductPlan::Cached { path })) if id.from_file => (
            format!(
                "the file you gave, imported into the model's product store ({})",
                file_name(path)
            ),
            false,
        ),
        (Some(order), Some(ProductPlan::Cached { path })) => (
            format!(
                "{order}: in the model's product store ({})",
                file_name(path)
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
        "Then bussard reads the device back at {target} and writes devices/{target}.toml with \
         its bussard.lock entry."
    ));
    let now = std::time::SystemTime::now();
    json!({
        "current_address": current.to_string(),
        "serial": v.serial.as_deref().map(hex),
        "mask": v.mask.map(|m| format!("{m:04X}")),
        "system_type": v.mask.map(bussard_mgmt::system_type),
        "manufacturer": v.manufacturer_id.map(bussard_mgmt::manufacturers::display),
        "order_number": v.order,
        "secure": v.secure.as_str(),
        "keeps_address": target == current,
        "product_data": product_data,
        "download_needed": download_needed,
        "sentences": sentences,
        "plan_digest": digest,
        "model_devices": model.devices.len(),
        "expires_at": tier.adds.expires_at(now),
    })
}

/// The `done` result: names first, one summary sentence.
fn done_result(adopted: &Adopted, dir: &std::path::Path, notes: Vec<String>) -> Value {
    let a = &adopted.assigned;
    let (target, current) = (a.target, a.current);
    let selected = adopted.selected.as_ref();
    let name = adopted.device.name.clone();
    let path = &adopted.path;
    let relative = path.strip_prefix(dir).unwrap_or(path).display().to_string();
    let product = selected.map(|s| {
        json!({
            "name": s.display_name(),
            "application": s.application_ref,
            "com_objects": s.com_objects.len(),
        })
    });
    let objects: Vec<Value> = useful_objects(&adopted.device, selected)
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
    let what = if a.written {
        format!("now answers at {target} (was {current})")
    } else {
        format!("answers at {target}")
    };
    let check = if a.matches_identified {
        "the read-back there matches the identified serial and mask"
    } else {
        "but the read-back there does NOT match the identified serial or mask"
    };
    let summary = format!("{name} ({target}) {what}; {check}; its device file is {relative}.");
    let next_step = match (&adopted.secure, selected) {
        (Some(_), _) => format!(
            "Tell the human the summary. Its links and parameters are in the model now; \
             knx_plan_device for {target} should report nothing to do."
        ),
        (None, Some(_)) => format!(
            "Tell the human the summary, then name the device and its room \
             (knx_rename_device or the device file) and wire its group objects: `objects` lists \
             them, transmit-capable first. knx_plan_device and knx_apply_device for {target} \
             write the links; a factory-fresh device needs its application loaded first (the \
             plan says so)."
        ),
        (None, None) => format!(
            "Tell the human the summary. It has no product data yet: knx_import_file with its \
             .knxprod attaches it; then wire its group objects and plan {target}."
        ),
    };
    json!({
        "ok": a.matches_identified,
        "step": "done",
        "name": name,
        "address": target.to_string(),
        "from": current.to_string(),
        "assigned": a.written,
        "verified": a.matches_identified,
        "readback": readback_json(&a.verified),
        "device_file": relative,
        "product": product,
        "objects": objects,
        "secure": adopted.secure.as_ref().map(|s| json!({
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
