//! The full application download (`bussard flash`, the MCP tier's
//! `method: flash`), once for both surfaces (issue #901).
//!
//! `bussard flash` runs [`probe`] (the read-only pre-flight: descriptor,
//! freshness probe, parameter memory, System 7 identity, PID 61), then
//! [`plan_full`] (the freshness verdict, the factory reset and the security
//! object it shapes the image with, the parameter-level plan, the gate) and
//! [`execute`] (the question, the download, its independent read-back and
//! the lock update). The MCP tier plans its download from the read
//! `knx_plan_device` made ([`flash_image`], [`load_need`]) and writes it
//! through the same [`execute`]. The image is [`FlashInputs`]'s, so the
//! offline oracle covers both.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use bussard_download::{
    CurrentMemory, DeviceFacts, FlashOptions, FlashPlan, Freshness, LiveTables, ParamPlan,
    PlanChange, PlanReport, ResidentState, SecureSenderEntry, Sys7Identity,
};
use bussard_mgmt::MgmtError;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::{IndividualAddress, Model};
use bussard_prod::{ApplicationProgram, ProductData};
use bussard_secure::{Key16, SequenceHighWater};
use sha2::{Digest, Sha256};

use super::params_only::ParamsRead;
use super::plan::put;
use super::read::DeviceRead;
use crate::flash::{DEVICE_OFFLINE_SECONDS, FlashInputs, Shape, com_object_words, flash_options};
use crate::flash_flow::{
    Flashed, FreshnessDecision, LockRecord, ReadbackInputs, decide_freshness, freshness_line,
    freshness_refusal, names_replacement,
};
use crate::observer::{Declined, Event, Note, Observer, Question, Step};
use crate::params::{BuiltPlan, ProductSource};
use crate::secure::SecureMaterial;
use crate::{BusService, FactsCache, Management, ServiceError};

/// The operator's choices for a flash.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlashChoices {
    /// `--force`: flash a device that carries another application.
    pub force: bool,
    /// `--full`: re-stream every object, and on System 7 unload first.
    pub full: bool,
    /// `--no-factory-reset`.
    pub no_factory_reset: bool,
    /// `--parameters-only`.
    pub parameters_only: bool,
}

/// What a flash of one device is planned from.
pub struct FlashRequest<'a> {
    /// The bus.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The checked source address.
    pub source: IndividualAddress,
    /// The model directory.
    pub dir: &'a Path,
    /// The model.
    pub model: Option<&'a Model>,
    /// The image inputs.
    pub inputs: &'a FlashInputs<'a>,
    /// The Data Secure material.
    pub material: &'a SecureMaterial,
    /// The extra secured senders of PID 54 (`--secure-sender`, the admitted
    /// tunnelling addresses).
    pub extra_senders: &'a [IndividualAddress],
    /// The command-wide send-sequence high-water mark (spec §5.9).
    pub high_water: SequenceHighWater,
    /// The BCU access key, `None` for free access.
    pub bcu_key: Option<u32>,
    /// The stored device facts (issue #209).
    pub facts: FactsCache,
    /// The operator's choices.
    pub choices: FlashChoices,
    /// Keep the pre-flight's connection for the write phase (issue #213).
    pub keep_connection: bool,
}

/// Why a flash stops before anything is written.
#[derive(Debug, thiserror::Error)]
pub enum FlashStop {
    /// The device descriptor could not be read.
    #[error("reading the device descriptor")]
    Descriptor {
        /// Whether the `T_Connect` established before the read.
        connected: bool,
        /// Whether the connection was secured.
        secure: bool,
        /// The failure.
        #[source]
        error: MgmtError,
    },
    /// The pre-flight could not run.
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// The plan is refused (`cannot flash: …`); `check` is the identity
    /// verdict when it was made before the refusal.
    #[error("{reason}")]
    Refused {
        /// The identity verdict against the lock.
        check: Option<Box<IdentityCheck>>,
        /// The reason.
        reason: String,
    },
}

/// What the read-only pre-flight found, with the plan for the device's mask.
pub struct Probed {
    /// The plan for the mask the device reports.
    pub plan: FlashPlan,
    /// The mask the device reports.
    pub device_mask: u16,
    /// What is resident on the device.
    pub resident: Option<ResidentState>,
    /// What the write phase need not rediscover.
    pub facts: DeviceFacts,
    /// The current parameter memory, when read.
    pub current: Option<CurrentMemory>,
    /// The parameter read of `--parameters-only`.
    pub params: Option<ParamsRead>,
    /// The System 7 identity read from the code sample.
    pub sys7: Option<Sys7Identity>,
    /// PID 61 of a Secure System B device.
    pub security_flags: Option<Vec<u8>>,
    /// The pre-flight's still-open connection, under `keep_connection`.
    pub kept: Option<Management>,
    /// When the pre-flight started.
    pub started: Instant,
}

/// Runs the read-only pre-flight ([`crate::flash_flow::probe`]) and builds
/// the plan for the mask the device reports. A flash rewrites the security
/// object, so the next plan reads PID 61 again (issue #336).
///
/// # Errors
///
/// The descriptor could not be read, the service failed, or the planner
/// refuses the application for the device's mask.
pub async fn probe(req: &FlashRequest<'_>) -> Result<Probed, FlashStop> {
    let started = Instant::now();
    let app = req.inputs.app();
    let request = crate::flash_flow::ProbeRequest {
        service: req.service,
        target: req.target,
        source: req.source,
        inputs: req.inputs,
        tool_key: req.material.tool_key.clone(),
        factory_key: req.material.fdsk.clone(),
        high_water: req.high_water.clone(),
        bcu_key: req.bcu_key,
        facts: req.facts.clone(),
        force: req.choices.force,
        parameters_only: req.choices.parameters_only,
        keep_connection: req.keep_connection,
    };
    let preread = async |l4: &mut Management, plan: &FlashPlan| {
        super::params_only::read_parameters_on(l4, plan, app).await
    };
    let mut probe = crate::flash_flow::probe(request, &preread).await?;
    crate::security_change::forget_flags(req.dir, req.target);
    let device_mask = match std::mem::replace(&mut probe.descriptor, Ok(0)) {
        Ok(mask) => mask,
        Err(error) => {
            // The kept connection is closed before the refusal.
            if let Some(l4) = probe.kept.take() {
                let _ = l4.disconnect().await;
            }
            return Err(FlashStop::Descriptor {
                connected: probe.connected,
                secure: req.material.tool_key.is_some(),
                error,
            });
        }
    };
    let plan = match probe.take_plan(req.inputs, device_mask) {
        Ok(plan) => plan,
        Err(err) => {
            if let Some(l4) = probe.kept.take() {
                let _ = l4.disconnect().await;
            }
            return Err(FlashStop::Refused {
                check: None,
                reason: err.to_string(),
            });
        }
    };
    Ok(Probed {
        plan,
        device_mask,
        resident: probe.resident,
        facts: probe.facts,
        current: probe.current,
        params: probe.preread,
        sys7: probe.sys7,
        security_flags: probe.security_flags,
        kept: probe.kept,
        started,
    })
}

/// A full download planned against what the pre-flight found.
pub struct FlashPlanned {
    /// The plan, shaped for the device (factory reset, `par` procedure,
    /// security object).
    pub plan: FlashPlan,
    /// The mask the device reports.
    pub device_mask: u16,
    /// What is resident on the device.
    pub resident: Option<ResidentState>,
    /// The identity verdict against the lock.
    pub check: IdentityCheck,
    /// The factory-freshness verdict the image is shaped by.
    pub freshness: Freshness,
    /// The gate's verdict (on System 7 the code sample decides).
    pub gate: Freshness,
    /// What the gate decided.
    pub decision: FreshnessDecision,
    /// The PID 54 table a secured download writes.
    pub senders: Option<Vec<SecureSenderEntry>>,
    /// A group address that leaves or joins Data Secure (issue #331).
    pub security_change: Option<PlanChange>,
    /// The parameter-level plan (issue #109).
    pub params: ParamPlan,
    /// The download options.
    pub options: FlashOptions,
    /// What the write phase need not rediscover.
    pub facts: DeviceFacts,
    /// How long the pre-flight took.
    pub preflight: Duration,
}

impl FlashPlanned {
    /// Whether the download skips objects whose resident image matches
    /// (re-flashing the same application without `--full`).
    pub fn differential(&self) -> bool {
        self.options.skip_matching_mcb
            && matches!(self.freshness, Freshness::SameApplication { .. })
    }

    /// The one question before the download, with the gate's line above it.
    pub fn question(&self, target: IndividualAddress, gateway: &str) -> Question {
        let writes = self
            .plan
            .steps
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    bussard_download::FlashStep::WriteRelMem { .. }
                        | bussard_download::FlashStep::WriteMem { .. }
                )
            })
            .count();
        let question = format!(
            "flash {} ({writes} memory write(s)) to {target} via {gateway}?",
            self.plan.identity.id
        );
        Question {
            kind: crate::observer::Ask::Write,
            prompt: match &self.decision.prompt_note {
                Some(note) => format!("{note}\n{question}"),
                None => question,
            },
            action: format!("flash {target} via {gateway}"),
        }
    }
}

/// Plans the full download from the pre-flight (whose kept connection the
/// caller took): the identity verdict, the
/// factory-freshness verdict that shapes the image, the security object of
/// a secured download, the security-object change, the parameter-level plan
/// and the gate's decision.
///
/// # Errors
///
/// The security program cannot be built.
pub fn plan_full(
    req: &FlashRequest<'_>,
    probed: Probed,
    gateway: &str,
) -> Result<FlashPlanned, FlashStop> {
    let Probed {
        mut plan,
        device_mask,
        resident,
        facts,
        current,
        sys7,
        security_flags,
        started,
        ..
    } = probed;
    let (target, model, choices) = (req.target, req.model, req.choices);
    let check = IdentityCheck::compare(
        model
            .and_then(|m| m.devices.get(&target))
            .map(|d| &d.device),
        ReportedIdentity {
            mask: bussard_model::facts::format_mask(device_mask),
            application_id: resident
                .as_ref()
                .and_then(|state| state.app_id.as_deref())
                .map(bussard_model::facts::format_application_id),
        },
    );
    let freshness = match &resident {
        Some(state) => bussard_download::assess_freshness(state, &plan.identity),
        None => Freshness::Unknown {
            reason: "the pre-flight probe did not run".to_string(),
        },
    };
    let shape = Shape {
        freshness: Some(&freshness),
        resident: resident.as_ref(),
        no_factory_reset: choices.no_factory_reset,
        unload_first: choices.full,
        model,
        target,
        material: req.material,
        extra_senders: req.extra_senders,
    };
    let senders = match req.inputs.finish(&mut plan, &shape) {
        Ok(senders) => senders,
        Err(err) => {
            return Err(FlashStop::Refused {
                check: Some(Box::new(check)),
                reason: err.to_string(),
            });
        }
    };
    let security_change = security_flags.as_deref().and_then(|flags| {
        let links = model
            .and_then(|m| m.links.links.get(&target))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        crate::security_change::from_flash_plan(target, &plan, links, flags)
            .and_then(|change| change.change(model))
    });
    // `--force` rewrites everything, so the device's values only fed the
    // display and were not read (issue #194).
    let skipped_for_force = choices.force
        && !plan.is_sys7()
        && resident
            .as_ref()
            .is_some_and(|r| r.has_loaded_application());
    let params = crate::flash_flow::parameter_plan(
        req.inputs.app(),
        req.inputs,
        &plan,
        &current.unwrap_or_default(),
        skipped_for_force,
    );
    let preflight = started.elapsed();
    let gate = bussard_download::flash_gate(&freshness, &plan, resident.as_ref(), sys7.as_ref());
    let decision = decide_freshness(target, gateway, req.dir, choices.force, &gate);
    let options = flash_options(req.bcu_key, choices.full, &plan, &freshness);
    Ok(FlashPlanned {
        plan,
        device_mask,
        resident,
        check,
        freshness,
        gate,
        decision,
        senders,
        security_change,
        params,
        options,
        facts,
        preflight,
    })
}

/// A download to run, from either surface.
pub struct FlashExecution<'a> {
    /// The bus.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The checked source address.
    pub source: IndividualAddress,
    /// The model directory (the lock).
    pub dir: &'a Path,
    /// The download.
    pub plan: &'a FlashPlan,
    /// Its options.
    pub options: FlashOptions,
    /// What the pre-flight learned.
    pub facts: DeviceFacts,
    /// The KNX Data Secure tool key.
    pub tool_key: Option<Key16>,
    /// The send-sequence high-water mark.
    pub high_water: SequenceHighWater,
    /// The pre-flight's connection to take over (issue #213).
    pub handover: Option<Management>,
    /// What the read-back compares with; `None` skips it.
    pub readback: Option<ReadbackInputs<'a>>,
    /// The PID 54 table the download writes, recorded in the lock once it
    /// verified; `None` records nothing.
    pub senders: Option<&'a [SecureSenderEntry]>,
    /// The question before the download.
    pub question: Question,
    /// Whether objects whose resident image matches are skipped (said
    /// before the download).
    pub differential: bool,
}

/// How a download ended.
pub struct FlashWritten {
    /// The download and its read-back.
    pub flashed: Flashed,
    /// What a download that loaded the application recorded in the lock.
    pub lock: Option<LockRecord>,
    /// When the download started.
    pub download_started: Instant,
    /// When the terminal restart began, when the download reached it.
    pub restart_started: Option<Instant>,
    /// When the read-back ended.
    pub finished: Instant,
}

/// Asks, then runs the download with its independent read-back on its last
/// connection, and records in the lock what a loaded download wrote to the
/// security object (PID 54, issue #297; PID 61, issue #331).
///
/// # Errors
///
/// The human said no, or no one could be asked.
pub async fn execute(
    exec: FlashExecution<'_>,
    observer: &mut impl Observer,
) -> Result<FlashWritten, Declined> {
    crate::observer::ask(observer, &exec.question)?;
    let plan = exec.plan;
    if plan.has_factory_reset() {
        observer.event(Event::Note(Note::Warn(
            "factory reset: the device's application, parameters and links are erased before the \
             download (its individual address is kept); every object is streamed in full. Pass \
             --no-factory-reset only when the device is known to hold no stale image."
                .to_string(),
        )));
    }
    if exec.differential {
        observer.event(Event::Note(Note::Warn(
            "differential download: objects whose resident image already matches are skipped \
             (pass --full to re-stream everything)"
                .to_string(),
        )));
    }
    let (target, dir, senders) = (exec.target, exec.dir, exec.senders);
    let run = crate::download::FlashRun {
        service: exec.service,
        target,
        source: exec.source,
        options: exec.options,
        facts: exec.facts,
        tool_key: exec.tool_key,
        high_water: exec.high_water,
        handover: exec.handover,
    };
    observer.event(Event::Step(Step::Download { plan }));
    let download_started = Instant::now();
    let mut timed = Timed {
        inner: observer,
        restart_started: None,
    };
    let flashed =
        crate::flash_flow::flash_and_verify(run, plan, &mut timed, exec.readback, target).await;
    let restart_started = timed.restart_started;
    let lock = matches!(&flashed.outcome, Ok(o) if o.ok())
        .then(|| crate::flash_flow::record_lock(dir, target, senders, plan));
    Ok(FlashWritten {
        flashed,
        lock,
        download_started,
        restart_started,
        finished: Instant::now(),
    })
}

/// Forwards a download's progress and notes when the terminal restart (the
/// last step) began.
struct Timed<'o, O: Observer> {
    inner: &'o mut O,
    restart_started: Option<Instant>,
}

impl<O: Observer> crate::observer::ProgressSink for Timed<'_, O> {
    fn event(&mut self, event: Event<'_>) {
        if let Event::Progress(bussard_download::Progress::Step { index, total, .. }) = &event
            && index == total
        {
            self.restart_started = Some(Instant::now());
        }
        self.inner.event(event);
    }
}

/// A full download a plan of `knx_plan_device` writes (issues #303, #750):
/// the image, its options, the PID 54 table it writes, and what the plan
/// reports.
pub struct FlashImage {
    /// The plan, shaped like `bussard flash --yes`.
    pub plan: FlashPlan,
    /// The download options (`bussard flash --yes`'s).
    pub options: FlashOptions,
    /// The PID 54 table a secured download writes.
    pub senders: Option<Vec<SecureSenderEntry>>,
    /// The resident object table the read found, seeding the download.
    pub object_table: Vec<(u8, u16)>,
    /// The device's `PID_MAX_APDU_LENGTH` from the facts the read checked
    /// (issue #761).
    pub max_apdu: Option<u16>,
    /// What the plan reports about the download.
    pub summary: FlashSummary,
    /// Why the application must be loaded (issue #750), `None` for a
    /// parameter change of the application the device runs.
    pub load: Option<String>,
    /// Whether the links are written after the download (issue #779).
    pub links_after: bool,
    /// What the device reported that the plan relied on, bound into the
    /// digest.
    binds: String,
}

impl FlashImage {
    /// The facts the download is seeded with.
    pub fn facts(&self) -> DeviceFacts {
        DeviceFacts {
            object_table: self.object_table.clone(),
            max_apdu: self.max_apdu,
            ..DeviceFacts::default()
        }
    }

    /// `model` extended with the image, so a plan digest binds the exact
    /// octets a flash writes.
    pub fn fingerprint(&self, model: [u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        put(&mut h, b"flash-v1");
        put(&mut h, &model);
        // The Debug rendering is stable within one build, which is all a
        // digest that lives for one server session needs.
        put(&mut h, format!("{:?}", self.plan).as_bytes());
        put(&mut h, format!("{:?}", self.options).as_bytes());
        // A yes to a load with the table write after it (issue #779) is a
        // yes to both.
        if self.links_after {
            put(&mut h, b"links-after");
        }
        // What the device reported, for a load (issue #750): a yes to
        // replacing one application is not a yes to replacing another.
        if self.load.is_some() {
            put(&mut h, b"load");
            put(&mut h, self.binds.as_bytes());
        }
        h.finalize().into()
    }
}

/// The `flash` field of a plan that writes the device with a full download.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlashSummary {
    /// Why the download is needed.
    pub why: String,
    /// The load of the pinned application (issue #750).
    pub load_application: Option<LoadApplication>,
    /// The identity line against the lock.
    pub identity: Option<String>,
    /// What the device runs now, as the gate sees it.
    pub resident: String,
    /// The com-objects that appear or disappear.
    pub objects: ObjectChanges,
    /// The table sizes before and after.
    pub tables: TableSizes,
    /// How long the device is offline.
    pub device_offline_seconds: Range,
    /// The parameter backup.
    pub parameter_backup: ParameterBackupNote,
    /// The pinned archive.
    pub product: PinnedProduct,
    /// Whether the download starts with a factory reset.
    pub factory_reset: bool,
    /// Whether objects whose image matches are skipped.
    pub differential: bool,
    /// Whether the links are written after the download (issue #779).
    pub links_after_download: bool,
}

/// The load of the pinned application.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadApplication {
    /// Why.
    pub why: String,
    /// The application loaded.
    pub application: String,
    /// What it replaces.
    pub replaces: String,
}

/// The com-objects a download shows and hides.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectChanges {
    /// Shown after the download.
    pub shown: Vec<ObjectWords>,
    /// Hidden after the download.
    pub hidden: Vec<ObjectWords>,
}

/// One com-object, in the product's words.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectWords {
    /// The object number.
    pub number: u16,
    /// Its text.
    pub text: Option<String>,
    /// Its DPT.
    pub dpt: Option<String>,
    /// The parameters behind the change.
    pub because: Vec<String>,
}

/// Table sizes before and after a download.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TableSizes {
    /// The address table.
    pub address: BeforeAfter,
    /// The association table.
    pub association: BeforeAfter,
    /// The group-object count (`before` unknown for a load).
    pub group_objects: BeforeAfter,
}

/// A count before and after.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BeforeAfter {
    /// Before.
    pub before: Option<usize>,
    /// After.
    pub after: usize,
}

/// A range of seconds.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Range {
    /// The least.
    pub min: u32,
    /// The most.
    pub max: u32,
}

/// Where the parameter memory is backed up before a download.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ParameterBackupNote {
    /// Whether it is backed up first (a load of a device without a readable
    /// application has none to keep).
    pub taken_first: bool,
    /// The backup directory.
    pub dir: String,
}

/// The pinned product archive a download writes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PinnedProduct {
    /// Its path in the model directory.
    pub archive: Option<String>,
    /// Its SHA-256, as the lock records it.
    pub product_sha256: String,
    /// The application.
    pub application: String,
}

/// What [`flash_image`] and [`load_need`] plan from: the read
/// `knx_plan_device` made.
pub struct FlashFor<'a> {
    /// The model directory.
    pub dir: &'a Path,
    /// The model.
    pub model: &'a Model,
    /// The device.
    pub target: IndividualAddress,
    /// The read.
    pub read: &'a DeviceRead<LiveTables>,
    /// The link-table plan.
    pub report: &'a PlanReport,
    /// The product data the lock pins.
    pub product: Option<&'a ProductSource>,
    /// The Data Secure material.
    pub material: &'a SecureMaterial,
    /// The admitted tunnelling addresses.
    pub tunnel: &'a [IndividualAddress],
}

/// Why a plan writes the device with a full download.
pub enum FlashNeed<'a> {
    /// The application bussard.lock pins must be loaded first (issue #750).
    Load(&'a LoadNeed),
    /// The model's parameter values change the group-object table (issue
    /// #303), which a parameter-only write cannot touch.
    Parameters(&'a BuiltPlan),
}

/// Why the application bussard.lock pins must be loaded (issue #750).
pub struct LoadNeed {
    /// The sentence the plan leads with.
    pub why: String,
}

/// The full download writing the model to the device, shaped as `bussard
/// flash` shapes it for the read's verdict. `Err` is a refusal reason.
///
/// # Errors
///
/// No pinned archive, a plan the device does not take, or the
/// factory-freshness gate.
pub fn flash_image(ctx: &FlashFor<'_>, need: FlashNeed<'_>) -> Result<FlashImage, String> {
    let (model, target, read) = (ctx.model, ctx.target, ctx.read);
    let (why, load) = match &need {
        FlashNeed::Load(need) => (need.why.clone(), Some(need.why.clone())),
        FlashNeed::Parameters(built) => (
            built
                .needs_flash
                .clone()
                .unwrap_or_else(|| "the group-object table changes".to_string()),
            None,
        ),
    };
    let pinned = pinned_product(
        model,
        target,
        ctx.product,
        &match &need {
            FlashNeed::Load(_) => why.clone(),
            FlashNeed::Parameters(_) => format!(
                "the model's parameter values change {target}'s group-object table ({why}), \
                 which needs a full download"
            ),
        },
    )?;
    let Some(app) = pinned.source.app() else {
        return Err(missing_app(target, pinned.source));
    };
    let params = read.params.as_ref();
    // A parameter change compares the com-objects the device shows now: its
    // parameter memory must have been read. A load only needs the probe.
    let (resident, before) = match &need {
        FlashNeed::Parameters(_) => {
            let Some(detail) = params.and_then(|p| p.detail.as_ref()) else {
                return Err(format!(
                    "{target}'s parameter memory was not read, so a full download cannot be \
                     planned; plan again"
                ));
            };
            (&detail.resident, Some(&detail.decoded.values))
        }
        FlashNeed::Load(_) => match params.and_then(|p| p.resident()) {
            Some(resident) => (resident, None),
            None => {
                return Err(format!(
                    "{target}'s resident application could not be probed, so loading {} cannot \
                     be planned; plan again",
                    app.id
                ));
            }
        },
    };
    let device_label = target.to_string();
    let (inputs, malformed) = FlashInputs::from_model(
        &pinned.source.product,
        app,
        &device_label,
        Some(model),
        target,
    );
    for warning in malformed {
        tracing::warn!("{warning}");
    }
    let mut plan = inputs
        .plan(read.live.tables().mask)
        .map_err(|e| format!("cannot flash {target}: {e}"))?;
    let (freshness, gate) = gate_for(&plan, resident, read);
    // The factory-freshness gate of `bussard flash` (issue #79), the same
    // function (issue #895). A load names the application it replaces in
    // the plan, so the yes to its digest is the chat's `--force` there
    // (issue #750); a parameter flash names none and gets no `--force`.
    let force = matches!(need, FlashNeed::Load(_)) && names_replacement(&gate);
    if let Some(refusal) = freshness_refusal(target, &gate, force) {
        return Err(match &need {
            FlashNeed::Load(_) => format!("{why}; {refusal}"),
            FlashNeed::Parameters(_) => refusal,
        });
    }
    let links_after = links_after(model, target, ctx.report, &plan, &freshness, resident);
    let before = before.map(|values| inputs.visible_objects(values));
    let because: Vec<String> = match &need {
        FlashNeed::Parameters(built) => built
            .parameters
            .iter()
            .map(|p| {
                format!(
                    "{} = {}, was {}",
                    p.key,
                    p.model,
                    p.device.as_deref().unwrap_or("unreadable")
                )
            })
            .collect(),
        FlashNeed::Load(_) => Vec::new(),
    };
    let shape = Shape {
        freshness: Some(&freshness),
        resident: Some(resident),
        no_factory_reset: false,
        // An application download, as `flash` without `--full`: no System 7
        // pre-download pass (issue #488).
        unload_first: false,
        model: Some(model),
        target,
        material: ctx.material,
        extra_senders: ctx.tunnel,
    };
    let senders = inputs
        .finish(&mut plan, &shape)
        .map_err(|e| format!("cannot flash {target}: {e}"))?;
    let options = flash_options(None, false, &plan, &freshness);
    let after = inputs.visible_objects(inputs.overrides());
    let objects = |numbers: &BTreeSet<u16>| -> Vec<ObjectWords> {
        numbers
            .iter()
            .map(|n| {
                let (text, dpt) = com_object_words(app, *n);
                ObjectWords {
                    number: *n,
                    text,
                    dpt,
                    because: because.clone(),
                }
            })
            .collect()
    };
    let (shown, hidden, objects_before) = match &before {
        Some(before) => (
            after.difference(before).copied().collect(),
            before.difference(&after).copied().collect(),
            Some(before.len()),
        ),
        // A load: every com-object the model's values show is new.
        None => (after.clone(), BTreeSet::new(), None),
    };
    let on_device = freshness_line(&gate);
    let report = ctx.report;
    let summary = FlashSummary {
        why,
        load_application: load.as_ref().map(|why| LoadApplication {
            why: why.clone(),
            application: app.id.clone(),
            replaces: on_device.clone(),
        }),
        identity: read.check().map(|c| crate::identity_line(target, c)),
        resident: on_device,
        objects: ObjectChanges {
            shown: objects(&shown),
            hidden: objects(&hidden),
        },
        tables: TableSizes {
            address: BeforeAfter {
                before: Some(report.current_address_count),
                after: report.resulting_address_count,
            },
            association: BeforeAfter {
                before: Some(report.current_association_count),
                after: report.resulting_association_count,
            },
            group_objects: BeforeAfter {
                before: objects_before,
                after: after.len(),
            },
        },
        device_offline_seconds: Range {
            min: DEVICE_OFFLINE_SECONDS.0,
            max: DEVICE_OFFLINE_SECONDS.1,
        },
        parameter_backup: ParameterBackupNote {
            taken_first: before.is_some(),
            dir: bussard_download::backup::parameter_backups_dir(ctx.dir)
                .display()
                .to_string(),
        },
        product: PinnedProduct {
            archive: pinned.archive,
            product_sha256: pinned.product_sha256,
            application: app.id.clone(),
        },
        factory_reset: plan.has_factory_reset(),
        differential: options.skip_matching_mcb,
        links_after_download: links_after,
    };
    let binds = format!(
        "{:?}|{:?}|{:?}",
        read.check().map(|c| &c.device),
        gate,
        resident.app_id
    );
    Ok(FlashImage {
        plan,
        options,
        senders,
        object_table: resident.object_table.clone(),
        max_apdu: read.seed().and_then(|seed| seed.max_apdu),
        summary,
        load,
        links_after,
        binds,
    })
}

/// The read's freshness verdict against `plan`'s application, which shapes
/// the image as `bussard flash` shapes it, and the gate's verdict: a System 7
/// device has no readable id, so the read's code sample decides there (issue
/// #314).
fn gate_for(
    plan: &FlashPlan,
    resident: &ResidentState,
    read: &DeviceRead<LiveTables>,
) -> (Freshness, Freshness) {
    let freshness = bussard_download::assess_freshness(resident, &plan.identity);
    let sys7 = read.params.as_ref().and_then(|p| p.sys7_identity.as_ref());
    let gate = bussard_download::flash_gate(&freshness, plan, Some(resident), sys7);
    (freshness, gate)
}

/// Whether the device needs the application bussard.lock pins loaded: it
/// runs another one (the identity verdict, or the System 7 code sample), has
/// none, or holds the pinned one unloaded. `None` when it runs the pinned
/// application, or when no product data is at hand to load. `Some(Err)` is
/// a refusal: the load is needed but the factory-freshness gate refuses it
/// without `--force`.
pub fn load_need(
    model: &Model,
    target: IndividualAddress,
    read: &DeviceRead<LiveTables>,
    product: Option<&ProductSource>,
) -> Option<Result<LoadNeed, String>> {
    let params = read.params.as_ref()?;
    let resident = params.resident()?;
    let source = product?;
    let app = source.app()?;
    let device_label = target.to_string();
    let (inputs, _) =
        FlashInputs::from_model(&source.product, app, &device_label, Some(model), target);
    let drift = read.check().is_some_and(IdentityCheck::is_drift);
    let plan = match inputs.plan(read.live.tables().mask) {
        Ok(plan) => plan,
        Err(err) if drift => {
            return Some(Err(format!(
                "{target} needs application {} loaded, and it cannot be planned for this device: \
                 {err}",
                app.id
            )));
        }
        Err(_) => return None,
    };
    // A property-only procedure loads no object (issue #390).
    if plan.is_property_only() {
        return None;
    }
    let (_, gate) = gate_for(&plan, resident, read);
    let why = crate::flash_flow::load_reason(target, read.check(), &gate, resident, &app.id)?;
    // The plan names the application a load replaces, and the yes to its
    // digest covers that (issue #750).
    if let Some(refusal) = freshness_refusal(target, &gate, names_replacement(&gate)) {
        return Some(Err(format!("{why}; {refusal}")));
    }
    Some(Ok(LoadNeed { why }))
}

/// Whether the links must be written after `plan`'s download (issue #779):
/// it loads no link table, and the links differ from the model, or the
/// factory reset it starts with erases the links the device holds while the
/// model has some.
fn links_after(
    model: &Model,
    target: IndividualAddress,
    report: &PlanReport,
    plan: &FlashPlan,
    freshness: &Freshness,
    resident: &ResidentState,
) -> bool {
    if crate::flash_flow::loads_link_tables(plan) {
        return false;
    }
    if !report.is_noop() {
        return true;
    }
    let mut probe = plan.clone();
    crate::flash::apply_freshness(&mut probe, Some(freshness), Some(resident), false, false);
    let has_links = model
        .links
        .links
        .get(&target)
        .is_some_and(|l| !l.is_empty());
    probe.erases_resident_objects() && has_links
}

/// The archive bussard.lock pins for the device.
struct Pinned<'p> {
    product_sha256: String,
    archive: Option<String>,
    source: &'p ProductSource,
}

/// The pinned archive of `target`, or the refusal naming `why` the download
/// is needed: a flash writes only a pinned archive.
fn pinned_product<'p>(
    model: &Model,
    target: IndividualAddress,
    product: Option<&'p ProductSource>,
    why: &str,
) -> Result<Pinned<'p>, String> {
    let device = model.devices.get(&target).map(|d| &d.device);
    let pinned = device.and_then(|d| {
        Some((
            d.lock.product_sha256.clone()?,
            d.lock.product_entry.as_ref()?.file.clone(),
        ))
    });
    let (Some((product_sha256, archive)), Some(source)) = (pinned, product) else {
        return Err(format!(
            "{why}, and bussard.lock pins no product archive for {target}: a flash writes only a \
             pinned archive. Run `bussard import-product` for the device's product (or `bussard \
             import` of the ETS export), then plan again."
        ));
    };
    if source.app().is_none() {
        return Err(missing_app(target, source));
    }
    Ok(Pinned {
        product_sha256,
        archive,
        source,
    })
}

/// The refusal for a pinned archive without the pinned application.
fn missing_app(target: IndividualAddress, source: &ProductSource) -> String {
    format!(
        "the pinned product archive does not carry application {}; run `bussard import-product` \
         for {target}'s product, then plan again",
        source.app_id
    )
}

/// The inputs of a flash's read-back from a product source.
pub fn readback_inputs<'a>(
    source: &'a ProductSource,
    model: Option<&'a Model>,
    device_mask: u16,
) -> Option<ReadbackInputs<'a>> {
    source.app().map(|app| ReadbackInputs {
        product: &source.product,
        app,
        model,
        device_mask,
    })
}

/// A download planned offline (`flash --dry-run`, the offline oracle).
pub struct Offline {
    /// The plan against the application's own mask, shaped by the recorded
    /// device state when one was given.
    pub plan: FlashPlan,
    /// The mask the application declares.
    pub device_mask: u16,
    /// The parameter-level plan: every value is new offline.
    pub params: ParamPlan,
    /// What the recorded device state decided (issue #490).
    pub recorded: Option<RecordedVerdict>,
}

/// What a recorded device state decided for an offline plan.
pub struct RecordedVerdict {
    /// The freshness verdict, in words (`holds this application (…)`).
    pub verdict: String,
    /// Whether the plan runs the product's `par` load procedure.
    pub par: bool,
    /// The objects whose recorded MCB matches the image, skipped.
    pub skipped: Vec<u8>,
}

/// Why an offline plan stops.
#[derive(Debug, thiserror::Error)]
pub enum OfflineStop {
    /// The application declares no usable mask.
    #[error("cannot plan offline: application program {0} declares no usable mask version")]
    NoMask(String),
    /// The plan is refused (`cannot flash: …`).
    #[error("{0}")]
    Refused(String),
    /// The recorded device state could not be read.
    #[error(transparent)]
    Recorded(#[from] super::FileError),
}

/// What an offline plan is made from.
#[derive(Clone, Copy)]
pub struct OfflineRequest<'a> {
    /// The image inputs.
    pub inputs: &'a FlashInputs<'a>,
    /// The model.
    pub model: Option<&'a Model>,
    /// The device.
    pub target: IndividualAddress,
    /// The recorded device state (`--resident`, issue #490).
    pub resident: Option<&'a Path>,
    /// The operator's choices.
    pub choices: FlashChoices,
    /// The Data Secure material.
    pub material: &'a SecureMaterial,
    /// The extra secured senders of PID 54.
    pub extra_senders: &'a [IndividualAddress],
}

/// Plans a download offline (`flash --dry-run`): against the mask the
/// application declares (what a matching device reports), shaped by the
/// device state recorded in `resident` (issue #490) as the live probe's
/// verdict shapes it. With `parameters_only` the plan is returned before the
/// security object is added (the parameter-only download writes none).
///
/// # Errors
///
/// No usable mask, a refused plan, or an unreadable recorded state.
pub fn plan_offline(req: &OfflineRequest<'_>) -> Result<Offline, OfflineStop> {
    let OfflineRequest {
        inputs,
        model,
        target,
        resident,
        choices,
        material,
        extra_senders,
    } = *req;
    let app = inputs.app();
    let device_mask = inputs
        .declared_mask()
        .ok_or_else(|| OfflineStop::NoMask(app.id.clone()))?;
    let mut plan = inputs
        .plan(device_mask)
        .map_err(|e| OfflineStop::Refused(e.to_string()))?;
    // The recorded objects are System B interface objects, or on a System 7
    // plan the load-state machines. A property-only plan keeps the offline
    // shape.
    let recorded = match resident {
        Some(path) if !choices.parameters_only && !plan.is_property_only() => {
            let recorded = super::resident::Recorded::read(path)?;
            let recorded = if plan.is_sys7() {
                recorded.into_sys7()
            } else {
                recorded
            };
            Some(recorded).filter(super::resident::Recorded::has_states)
        }
        _ => None,
    };
    let freshness = recorded
        .as_ref()
        .map(|r| bussard_download::assess_freshness(&r.state, &plan.identity));
    crate::flash::apply_freshness(
        &mut plan,
        freshness.as_ref(),
        recorded.as_ref().map(|r| &r.state),
        choices.no_factory_reset,
        choices.full,
    );
    if choices.parameters_only {
        return Ok(Offline {
            plan,
            device_mask,
            params: ParamPlan::default(),
            recorded: None,
        });
    }
    inputs
        .add_security_steps(&mut plan, model, target, material, extra_senders)
        .map_err(|e| OfflineStop::Refused(e.to_string()))?;
    let recorded = match (&recorded, &freshness) {
        (Some(recorded), Some(freshness)) => {
            let verdict = match freshness {
                Freshness::Fresh => "no loaded application".to_string(),
                Freshness::SameApplication { resident } => {
                    format!("holds this application ({resident})")
                }
                Freshness::Resident { resident, .. } => format!(
                    "holds another application ({})",
                    resident.as_deref().unwrap_or("unidentified")
                ),
                Freshness::Mismatch { reason } | Freshness::Unknown { reason } => reason.clone(),
            };
            let par = plan.is_par_procedure();
            let skipped = if !plan.is_sys7()
                && crate::flash::skip_unchanged(choices.full, &plan, freshness)
            {
                recorded.skip_matching(&mut plan)
            } else {
                Vec::new()
            };
            Some(RecordedVerdict {
                verdict,
                par,
                skipped,
            })
        }
        _ => None,
    };
    // Offline there is no current value to read back: every value is new.
    let params =
        crate::flash_flow::parameter_plan(app, inputs, &plan, &CurrentMemory::new(), false);
    Ok(Offline {
        plan,
        device_mask,
        params,
        recorded,
    })
}

/// The programs a flash parses out of an archive (issue #214): by order
/// number, by `application`, else the program the lock pins (`pinned`, so an
/// ETS export needs no `--application`), else every program (the
/// sole-application rule needs them all).
pub fn app_selection(
    catalog: &bussard_prod::ProductCatalog,
    order_number: Option<&str>,
    application: Option<&str>,
    pinned: Option<&str>,
) -> bussard_prod::AppSelection {
    match (order_number, application.or(pinned)) {
        (Some(order), _) => {
            bussard_prod::AppSelection::Only(crate::params::order_refs(catalog, order))
        }
        (None, Some(wanted)) => by_application(catalog, wanted),
        (None, None) => bussard_prod::AppSelection::All,
    }
}

/// The selection of the one program `wanted` names, by the rule of
/// [`bussard_download::select_application`] (the exact id, else the one
/// program with the same manufacturer, number and version). Anything that
/// rule would refuse selects every program, so the refusal reads exactly as
/// before.
fn by_application(
    catalog: &bussard_prod::ProductCatalog,
    wanted: &str,
) -> bussard_prod::AppSelection {
    match crate::params::select_id(catalog, wanted) {
        Some(id) => bussard_prod::AppSelection::Only(vec![id]),
        None => bussard_prod::AppSelection::All,
    }
}

/// Resolves an application program from a hardware order number, requiring
/// exactly one match.
///
/// # Errors
///
/// No or several applications match.
pub fn resolve_by_order_number<'a>(
    product: &'a ProductData,
    order_number: &str,
) -> Result<&'a ApplicationProgram, bussard_download::model_params::OrderNumberError> {
    bussard_download::resolve_by_order_number(product, order_number)
}

/// The application program a flash downloads: by `order_number` (exactly
/// one match), else `application`, else the program the device file pins
/// when the archive has it, else the order number's when the archive has
/// several, else the sole one. `Err` is the sentence a surface prints.
///
/// # Errors
///
/// No program, or more than one, matches.
pub fn select_app<'a>(
    product: &'a ProductData,
    order_number: Option<&str>,
    application: Option<&str>,
    device: Option<&bussard_model::schema::Product>,
) -> Result<&'a ApplicationProgram, String> {
    if let Some(order) = order_number {
        return resolve_by_order_number(product, order).map_err(|err| err.to_string());
    }
    let candidates: Vec<&ApplicationProgram> = product.applications.iter().collect();
    let pinned = device
        .and_then(|p| p.application_ref.as_deref())
        .filter(|id| bussard_download::select_application(&candidates, Some(id)).is_ok());
    let by_order = device
        .and_then(|p| p.order_number.as_deref())
        .and_then(|order| resolve_by_order_number(product, order).ok())
        .map(|app| app.id.as_str());
    let application = application
        .or(pinned)
        .or(if candidates.len() > 1 { by_order } else { None });
    bussard_download::select_application(&candidates, application)
        .map_err(|err| format!("cannot select an application program: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_prod::{AppSelection, parse_application_program};
    use std::collections::BTreeMap;

    /// The overrides `bussard flash` plans with (the warnings dropped).
    fn collect_parameter_overrides(
        model: Option<&bussard_model::Model>,
        target: IndividualAddress,
    ) -> BTreeMap<String, String> {
        bussard_download::parameter_overrides(model, target).0
    }

    fn catalog(ids: &[&str]) -> bussard_prod::ProductCatalog {
        bussard_prod::ProductCatalog {
            application_ids: ids.iter().map(|s| s.to_string()).collect(),
            ..bussard_prod::ProductCatalog::default()
        }
    }

    #[test]
    fn test_by_application_exact_and_same_program() {
        let cat = catalog(&["M-0004_A-A011-13-400D-O000A", "M-0004_A-B022-10-1111-O000A"]);
        assert_eq!(
            by_application(&cat, "M-0004_A-A011-13-400D-O000A"),
            AppSelection::Only(vec!["M-0004_A-A011-13-400D-O000A".to_string()])
        );
        // Another build hash of the same program (issue #142).
        assert_eq!(
            by_application(&cat, "M-0004_A-A011-13-60BC-O000A"),
            AppSelection::Only(vec!["M-0004_A-A011-13-400D-O000A".to_string()])
        );
    }

    #[test]
    fn test_by_application_unknown_selects_all() {
        let cat = catalog(&["M-0004_A-A011-13-400D-O000A"]);
        assert_eq!(
            by_application(&cat, "M-0083_A-0001-10-0000"),
            AppSelection::All
        );
    }

    /// Builds a one-device model whose device at `addr` carries `params`.
    fn model_with_params(addr: &str, params: &[(&str, &str)]) -> bussard_model::Model {
        use bussard_model::schema::Device;
        let address: IndividualAddress = addr.parse().expect("test fixture");
        let device = Device {
            address,
            name: "test".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: Default::default(),
            parameters: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            security: None,
            application_override: None,
            knxnet: None,
            lock: Default::default(),
        };
        let mut devices = std::collections::BTreeMap::new();
        devices.insert(
            address,
            bussard_model::loader::LoadedDevice {
                device,
                file_stem: "test".to_string(),
            },
        );
        bussard_model::Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices,
        }
    }

    #[test]
    fn parameter_overrides_are_rekeyed_to_ref_id() -> Result<(), Box<dyn std::error::Error>> {
        // A device file keys parameters `<slug>@<ref-id>`; collection drops the
        // slug and keys by the ETS-stable ref id (the part after @).
        let target: IndividualAddress = "1.1.4".parse()?;
        let model = model_with_params(
            "1.1.4",
            &[
                ("windalarm-1@MD-1_M-3_MI-1_P-3_R-45", "1"),
                ("nachtabsenkung@P-1312_R-2140", "18"),
            ],
        );
        let out = collect_parameter_overrides(Some(&model), target);
        assert_eq!(
            out.get("MD-1_M-3_MI-1_P-3_R-45").map(String::as_str),
            Some("1")
        );
        assert_eq!(out.get("P-1312_R-2140").map(String::as_str), Some("18"));
        // The human slug is gone from the key entirely.
        assert!(!out.keys().any(|k| k.contains('@')));
        Ok(())
    }

    #[test]
    fn malformed_parameter_key_without_at_is_skipped() -> Result<(), Box<dyn std::error::Error>> {
        // A key with no `@` has no determinable ref-id identity; it is skipped
        // rather than fed to the engine as a bogus ref id.
        let target: IndividualAddress = "1.1.4".parse()?;
        let model = model_with_params("1.1.4", &[("bogus_no_at_sign", "5")]);
        let out = collect_parameter_overrides(Some(&model), target);
        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn no_model_or_unknown_device_yields_no_overrides() -> Result<(), Box<dyn std::error::Error>> {
        let target: IndividualAddress = "1.1.4".parse()?;
        assert!(collect_parameter_overrides(None, target).is_empty());
        // A model that has no device at the target address contributes nothing.
        let model = model_with_params("1.1.9", &[("x@P-1_R-1", "1")]);
        assert!(collect_parameter_overrides(Some(&model), target).is_empty());
        Ok(())
    }

    /// A minimal parseable single-segment System B application under id `id`.
    fn app(id: &str) -> ApplicationProgram {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
             <ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1"
                MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
              <Static>
               <Code>
                <RelativeSegment Id="{id}_RS-1" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
               </Code>
               <LoadProcedures>
                <LoadProcedure><LdCtrlConnect /><LdCtrlDisconnect /></LoadProcedure>
               </LoadProcedures>
              </Static>
             </ApplicationProgram></KNX>"#
        );
        parse_application_program(id, xml.as_bytes()).expect("test fixture")
    }

    /// Builds a [`ProductData`] from `(order_number, [app_ref…])` rows and the
    /// application ids present in the archive.
    fn product(rows: &[(&str, &[&str])], app_ids: &[&str]) -> ProductData {
        let mut data = ProductData {
            manufacturers: vec!["M-0083".to_string()],
            ..ProductData::default()
        };
        for id in app_ids {
            data.applications.push(app(id));
        }
        for (order, refs) in rows {
            data.hardware.order_to_apps.insert(
                order.to_string(),
                refs.iter().map(|r| r.to_string()).collect(),
            );
        }
        data
    }

    #[test]
    fn resolves_exactly_one_match() -> Result<(), Box<dyn std::error::Error>> {
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-000D-23-5BFD"])],
            &["M-0083_A-000D-23-5BFD"],
        );
        let app = resolve_by_order_number(&data, "AKK-0216.03")?;
        assert_eq!(app.id, "M-0083_A-000D-23-5BFD");
        Ok(())
    }

    #[test]
    fn resolution_normalizes_case_and_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        // Index-style normalization: trim + upper-case, interior separators kept.
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-000D-23-5BFD"])],
            &["M-0083_A-000D-23-5BFD"],
        );
        let app = resolve_by_order_number(&data, "  akk-0216.03 ")?;
        assert_eq!(app.id, "M-0083_A-000D-23-5BFD");
        Ok(())
    }

    #[test]
    fn zero_matches_lists_known_order_numbers() {
        let data = product(
            &[
                ("AKK-0216.03", &["M-0083_A-1"]),
                ("AKK-0416.03", &["M-0083_A-1"]),
            ],
            &["M-0083_A-1"],
        );
        let err = resolve_by_order_number(&data, "NOPE-9").expect_err("expected an error");
        let msg = err.to_string();
        assert!(msg.contains("no application matches order number"), "{msg}");
        assert!(
            msg.contains("AKK-0216.03"),
            "should list known order numbers: {msg}"
        );
        assert!(
            msg.contains("--application"),
            "should point at the fallback: {msg}"
        );
    }

    #[test]
    fn multiple_matches_lists_candidate_ids() {
        // One order number mapping to two distinct applications is ambiguous.
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-1", "M-0083_A-2"])],
            &["M-0083_A-1", "M-0083_A-2"],
        );
        let err = resolve_by_order_number(&data, "AKK-0216.03").expect_err("expected an error");
        let msg = err.to_string();
        assert!(msg.contains("maps to 2 applications"), "{msg}");
        assert!(
            msg.contains("M-0083_A-1") && msg.contains("M-0083_A-2"),
            "{msg}"
        );
        assert!(msg.contains("--application"), "{msg}");
    }

    #[test]
    fn duplicate_refs_across_rows_collapse_to_one() -> Result<(), Box<dyn std::error::Error>> {
        // Two order-number rows pointing at the same application resolve cleanly.
        let data = product(
            &[
                ("AKK-0216.03", &["M-0083_A-1"]),
                ("AKK-0216.03 ", &["M-0083_A-1"]),
            ],
            &["M-0083_A-1"],
        );
        let app = resolve_by_order_number(&data, "AKK-0216.03")?;
        assert_eq!(app.id, "M-0083_A-1");
        Ok(())
    }

    // --- The factory-freshness gate (issue #79) -----------------------------
}
