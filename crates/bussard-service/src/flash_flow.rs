//! The flow of a full application download (issue #750): the read-only
//! pre-flight, the factory-freshness decision, the parameter-level plan, the
//! download with its independent read-back, and the lock update, as
//! functions with no I/O of their own.
//!
//! `bussard flash` and the MCP tier's `knx_apply_device` (when its plan says
//! the application must be loaded) both run a flash through these functions:
//! progress goes to a [`FlashObserver`], and what the front end must tell
//! the human (the freshness paragraph, the line folded into the
//! confirmation, the recovery advice, what was recorded in the lock) comes
//! back as values. The CLI prints them and asks on the terminal; the MCP
//! tool puts them in its JSON and asks for the plan digest. The image itself
//! is built by [`crate::flash::FlashInputs`], so the offline oracle
//! (`scripts/campaign/95-offline-oracle.sh`) covers both surfaces.

use std::path::Path;

use bussard_download::{
    CurrentMemory, DeviceFacts, FlashOutcome, FlashPlan, Freshness, ParamPlan, PlanError,
    ResidentState, SecureSenderEntry, Sys7Identity, probe_resident_state,
    read_current_parameter_memory,
};
use bussard_mgmt::load::WriteError;
use bussard_mgmt::{MaskProfile, MgmtError};
use bussard_model::identity::IdentityCheck;
use bussard_model::{IndividualAddress, Model};
use bussard_prod::{ApplicationProgram, ProductData};
use bussard_secure::{Key16, SequenceHighWater};

use crate::bus::{Authorize, BusService, L4Options, Management};
use crate::download::{FlashObserver, FlashRun};
use crate::error::ServiceError;
use crate::facts::{FactsCache, FactsSource, FactsWant};
use crate::flash::FlashInputs;
use crate::verify::{Expected, WriteReadback};

/// How often the read-only pre-flight runs before its result stands, when a
/// connection loss interrupts it (issue #177).
pub const PREFLIGHT_ATTEMPTS: u32 = 3;

/// The note the parameter plan carries when `--force` skipped the read-back.
pub const FORCE_SKIPS_READBACK_NOTE: &str = "current values not read back: --force rewrites the \
     whole application, so the device's parameter memory only fed this display (issue #194)";

/// What the read-only pre-flight of a flash needs.
pub struct ProbeRequest<'a> {
    /// The service the connection is leased from.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The checked source address.
    pub source: IndividualAddress,
    /// The image inputs: the plan is built for the mask the device reports.
    pub inputs: &'a FlashInputs<'a>,
    /// The KNX Data Secure tool key, `None` on the plain path.
    pub tool_key: Option<Key16>,
    /// The factory key of a device reset to default (issue #532).
    pub factory_key: Option<Key16>,
    /// The send-sequence high-water mark shared by the whole flash.
    pub high_water: SequenceHighWater,
    /// The BCU access key, `None` for free access.
    pub bcu_key: Option<u32>,
    /// The stored device facts (issue #209).
    pub facts: FactsCache,
    /// `--force`: the device's code and parameters are not read for display.
    pub force: bool,
    /// `--parameters-only`: the parameter regions are read by `preread`.
    pub parameters_only: bool,
    /// Keep a complete pre-flight's connection for the write phase (issue
    /// #213): nothing waits between the two.
    pub keep_connection: bool,
}

/// What the read-only pre-flight found.
pub struct Probe<P> {
    /// Whether the `T_Connect` established before the first read.
    pub connected: bool,
    /// The device descriptor (mask) read.
    pub descriptor: Result<u16, MgmtError>,
    /// What is resident on the device (issue #79).
    pub resident: Option<ResidentState>,
    /// What the write phase need not rediscover: the authorize verdict, the
    /// max APDU, the object table.
    pub facts: DeviceFacts,
    /// The current parameter memory (issue #109), when read.
    pub current: Option<CurrentMemory>,
    /// The parameter read of `--parameters-only`, when made.
    pub preread: Option<P>,
    /// The System 7 identity read from the code sample (issue #314).
    pub sys7: Option<Sys7Identity>,
    /// PID 61 of a Secure System B device (issue #331).
    pub security_flags: Option<Vec<u8>>,
    /// The pre-flight's still-open connection, under `keep_connection`.
    pub kept: Option<Management>,
    /// The plan for the mask the application declares, built before the
    /// connection opened.
    precomputed: Option<(u16, Result<FlashPlan, PlanError>)>,
}

impl<P> Probe<P> {
    /// The plan for `mask`, reusing the one built before the connection when
    /// the device reports the declared mask.
    ///
    /// # Errors
    ///
    /// The planner refuses the application for this mask.
    pub fn take_plan(
        &mut self,
        inputs: &FlashInputs<'_>,
        mask: u16,
    ) -> Result<FlashPlan, PlanError> {
        match self.precomputed.take() {
            Some((declared, plan)) if declared == mask => plan,
            _ => inputs.plan(mask),
        }
    }
}

/// Runs the read-only pre-flight of a flash on one connection: the authorize
/// (or the stored facts' verdict), the device descriptor, the device facts,
/// the max APDU, the factory-freshness probe, the current parameter memory,
/// the `--parameters-only` read (`preread`), the System 7 identity and PID
/// 61. A connection loss in the middle re-runs it on a fresh connection, up
/// to [`PREFLIGHT_ATTEMPTS`] times. Nothing is written.
///
/// # Errors
///
/// A service failure other than a management error (those are the
/// descriptor's result).
pub async fn probe<P>(
    req: ProbeRequest<'_>,
    preread: &impl AsyncFn(&mut Management, &FlashPlan) -> P,
) -> Result<Probe<P>, ServiceError> {
    let ProbeRequest {
        service,
        target,
        source,
        inputs,
        tool_key,
        factory_key,
        high_water,
        bcu_key,
        facts: mut device_facts,
        force,
        parameters_only,
        keep_connection,
    } = req;
    let handle = service.handle();
    // The plan for the mask the application declares, which is what a
    // matching device reports: built before the device connection opens, so
    // planning a large application never holds an idle Layer-4 connection (a
    // device drops one after 6 s of silence).
    let precomputed = inputs.declared_mask().map(|mask| (mask, inputs.plan(mask)));
    // The device facts (issue #209): a valid set spares the pre-flight its
    // object walk and max-APDU read, and their authorize verdict decides
    // whether the free-access key is presented (issue #215).
    let skip_authorize = bcu_key.is_none() && device_facts.may_skip_authorize(target);
    if skip_authorize {
        device_facts.defer_authorize(bussard_mgmt::apci::FREE_ACCESS_KEY);
    }
    let device_facts = device_facts;
    let secure_probe = tool_key.is_some();
    let mut attempt = 1u32;
    loop {
        let losses_before = handle.link_losses();
        // A device reset to default is named, not flashed (issue #532).
        let probe_options = L4Options::secured(source, tool_key.clone(), high_water.clone())
            .with_factory_key(factory_key.clone())
            .with_authorize(Authorize::Skip);
        // What this read-only pass learns about the device, handed to the
        // write phase so it does not rediscover any of it.
        let mut facts = DeviceFacts::default();
        let session = match service.connect_l4_retrying(target, &probe_options).await {
            Ok(mut dev) => {
                let mut body = async |dev: &mut Management| {
                    // Tolerate a device that does not implement authorize.
                    let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
                    let r = if skip_authorize {
                        bussard_mgmt::read_device_descriptor(dev).await
                    } else {
                        match dev.authorize_or_fail(key).await {
                            Ok(outcome) => {
                                // Remember the verdict: a device that does not
                                // implement authorize must not be asked again in
                                // the write phase.
                                facts.authorize = Some(outcome);
                                bussard_mgmt::read_device_descriptor(dev).await
                            }
                            Err(err) => Err(err),
                        }
                    };
                    // The stored device facts on System B, the family whose
                    // freshness probe walks the objects.
                    let mut facts_cached = false;
                    if let Ok(mask) = &r
                        && MaskProfile::from_mask(*mask).tables_supported()
                    {
                        match device_facts.establish(dev, *mask, FactsWant::Table).await {
                            Ok(established) => {
                                facts_cached = established.source == FactsSource::Cached;
                            }
                            Err(err) => tracing::debug!("{target} device facts: {err}"),
                        }
                    }
                    // A skipped authorize stands only on facts that matched
                    // this device; otherwise present the key now.
                    if skip_authorize {
                        if !facts_cached && dev.last_authorize().is_none() {
                            let _ = dev.authorize_or_fail(key).await;
                        }
                        facts.authorize = Some(dev.last_authorize().cloned().unwrap_or(
                            bussard_mgmt::AuthorizeOutcome::Unsupported {
                                detail:
                                    "the device facts record no answer to A_Authorize".to_string(),
                            },
                        ));
                    }
                    // PID_MAX_APDU_LENGTH is device-stable: negotiated here, on
                    // the read-only connection, so the write phase seeds it.
                    facts.max_apdu = dev.negotiate_max_apdu().await.ok().flatten();
                    facts.max_apdu_absent =
                        dev.max_apdu_absence() == Some(bussard_mgmt::MaxApduAbsence::Answered);
                    // The factory-freshness probe (issue #79), once the mask
                    // is known.
                    let resident = match &r {
                        Ok(mask) => Some(
                            probe_resident_state(
                                dev,
                                *mask,
                                None,
                                bussard_download::ProbeScope::Decisive,
                            )
                            .await,
                        ),
                        Err(_) => None,
                    };
                    if let Some(state) = &resident {
                        facts.object_table = state.object_table.clone();
                        facts.association_pdt = state.association_pdt;
                    }
                    // The plan needs only the mask; the parameter read-back
                    // (issue #109) rides this same connection.
                    let replanned;
                    let planned = match (&r, &precomputed) {
                        (Ok(mask), Some((declared, Ok(plan)))) if mask == declared => Some(plan),
                        (Ok(mask), _) => {
                            replanned = inputs.plan(*mask);
                            replanned.as_ref().ok()
                        }
                        (Err(_), _) => None,
                    };
                    let current = match (planned, &resident) {
                        (Some(plan), Some(state))
                            if wants_current_parameters(force, parameters_only, state)
                                && !plan.is_sys7() =>
                        {
                            Some(
                                read_current_parameter_memory(dev, plan, &facts.object_table).await,
                            )
                        }
                        _ => None,
                    };
                    // `--parameters-only` reads the parameter regions on this
                    // connection too, once the identity gate passes (issue
                    // #215).
                    let pre = match (planned, &resident) {
                        (Some(plan), Some(_))
                            if parameters_only
                                && bussard_download::identity_gate(plan, resident.as_ref())
                                    .is_ok() =>
                        {
                            Some(preread(dev, plan).await)
                        }
                        _ => None,
                    };
                    // System 7 has no readable application id: the code
                    // sample stands in for it (issue #314).
                    let sys7 = match (planned, &resident) {
                        (Some(plan), Some(state))
                            if !force
                                && !parameters_only
                                && bussard_download::needs_sys7_identity(plan, state) =>
                        {
                            Some(bussard_download::sys7_identity(dev, plan, state).await)
                        }
                        _ => None,
                    };
                    // PID 61 of a Secure System B device (issue #331).
                    // Informational: a refused read leaves it out.
                    let flags = match planned {
                        Some(plan) if secure_probe && !plan.is_sys7() && !parameters_only => {
                            bussard_download::read_security_flags(dev)
                                .await
                                .ok()
                                .flatten()
                        }
                        _ => None,
                    };
                    Ok::<_, ServiceError>((r, resident, current, (pre, sys7, flags)))
                };
                let outcome = body(&mut dev).await;
                // Keep a complete pre-flight's connection for the write phase
                // (issue #213); an interrupted or failed one is closed.
                let complete = matches!(
                    &outcome,
                    Ok((Ok(_), Some(state), _, _)) if !state.interrupted
                );
                let kept = if keep_connection && complete {
                    Some(dev)
                } else {
                    let _ = dev.disconnect().await;
                    None
                };
                outcome.map(|parts| (parts, kept))
            }
            Err(err) => Err(err),
        };
        let (connected, descriptor, resident, current, preread_result, sys7, flags, kept) =
            match session {
                Ok(((r, resident, current, (pre, sys7, flags)), kept)) => {
                    (true, r, resident, current, pre, sys7, flags, kept)
                }
                Err(ServiceError::Mgmt(err)) => {
                    (false, Err(err), None, None, None, None, None, None)
                }
                Err(err) => return Err(err),
            };
        // A loss still being re-established counts too (issue #192).
        let link_lost = handle.link_losses() != losses_before
            || handle.status() == bussard_bus::BusState::Reconnecting;
        if attempt >= PREFLIGHT_ATTEMPTS
            || !preflight_interrupted(&descriptor, resident.as_ref(), link_lost)
        {
            return Ok(Probe {
                connected,
                descriptor,
                resident,
                facts,
                current,
                preread: preread_result,
                sys7,
                security_flags: flags,
                kept,
                precomputed,
            });
        }
        attempt += 1;
        tracing::warn!(
            "the read-only pre-flight of {target} was interrupted by a connection loss; \
             retrying (attempt {attempt} of {PREFLIGHT_ATTEMPTS})"
        );
        // An interrupted pre-flight kept no connection (`complete` above).
        drop(kept);
        handle.wait_connected(handle.reconnect_budget()).await;
    }
}

/// Whether a pre-flight attempt was cut short by a connection loss and should
/// be re-run: the resident-state probe was interrupted by a connection death,
/// or the descriptor read failed with a lost gateway link, or with any
/// connection death while the bus reported a link loss (`link_lost`).
pub fn preflight_interrupted(
    descriptor: &Result<u16, MgmtError>,
    resident: Option<&ResidentState>,
    link_lost: bool,
) -> bool {
    match descriptor {
        Err(MgmtError::Transport(e)) => e.is_link_loss(),
        Err(
            MgmtError::NoResponse { .. }
            | MgmtError::Disconnected { .. }
            | MgmtError::MidSessionSilence { .. },
        ) => link_lost,
        Err(_) => false,
        Ok(_) => resident.is_some_and(|state| state.interrupted),
    }
}

/// Whether the pre-flight reads the device's current parameter memory for the
/// parameter plan (issue #109).
///
/// Only a device that already carries an application has a segment to read.
/// `--force` is a full rewrite whose read-back only fed the "N change(s)"
/// display, so it is skipped there (issue #194), and `--parameters-only` reads
/// the regions itself, with their addresses, on its own path.
pub fn wants_current_parameters(
    force: bool,
    parameters_only: bool,
    resident: &ResidentState,
) -> bool {
    !force && !parameters_only && resident.has_loaded_application()
}

/// The sentence for a failed device-descriptor read whose shape names a
/// cause, `None` when the error speaks for itself.
///
/// The KNX Virtual IP-medium devices (order `*.ip`) accept the `T_Connect`
/// but `T_Disconnect` on the very first descriptor read, and a KNX Data
/// Secure device drops a management APDU it cannot accept; both reach
/// bussard as "the device accepted the connection and then said nothing".
pub fn descriptor_read_message(
    target: IndividualAddress,
    connected: bool,
    secure: bool,
    err: &MgmtError,
) -> Option<String> {
    let sync_unanswered = matches!(
        err,
        MgmtError::Secure {
            source: bussard_secure::AsduError::SyncUnanswered,
            ..
        }
    );
    // The descriptor read can follow an authorize and a max-APDU read, so a
    // silent device shows up as a mid-session silence rather than a bare
    // `NoResponse`; it is the same symptom.
    let silent = matches!(
        err,
        MgmtError::NoResponse { .. }
            | MgmtError::MidSessionSilence {
                kind: bussard_mgmt::SilenceKind::NoResponse,
                ..
            }
    );
    let disconnected = matches!(err, MgmtError::Disconnected { .. });
    if connected && (sync_unanswered || silent || disconnected) {
        if secure {
            return Some(format!(
                "{target} accepted the connection but never answered the SECURED management \
                 access. A KNX Data Secure device drops a frame it cannot authenticate, so \
                 either the tool key is not this device's key (the MAC does not verify), or the \
                 device is not security-activated at all and ignores A_SecureData — in which \
                 case flash it without --keyring/--tool-key. Nothing was written."
            ));
        }
        if silent {
            return Some(format!(
                "{target} accepted the connection but never answered the plain management \
                 access. If this device is KNX Data Secure-activated it refuses unsecured \
                 management: {}. Nothing was written.",
                crate::guidance::tool_key_hint()
            ));
        }
    }
    if connected && disconnected {
        return Some(format!(
            "{target} accepted the connection but disconnected on the first read: typical for \
             devices whose management is gated on a loaded application or a different medium \
             profile (e.g. KNX Virtual IP-medium `*.ip` devices, which disconnect on descriptor \
             reads while their `*.tp` siblings answer). Flash targets the application download, \
             which this device is not accepting management for over this connection. It is also \
             what a KNX Data Secure-activated device does to unsecured management: if this \
             device is activated, {}.",
            crate::guidance::tool_key_hint()
        ));
    }
    None
}

/// What the factory-freshness gate decided: what to tell the operator, whether
/// the flash may go ahead, and the line the confirmation prompt carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessDecision {
    /// The paragraph shown after the plan, before the confirmation.
    pub message: String,
    /// Whether the flash continues. `false` is a refusal: nothing is written.
    pub proceed: bool,
    /// The refusal in one sentence ([`freshness_refusal`]), `Some` exactly
    /// when `proceed` is `false`.
    pub refusal: Option<String>,
    /// The one-line warning folded into the confirmation when the device is
    /// not factory-fresh, so a yes is given against what is being destroyed.
    pub prompt_note: Option<String>,
}

/// Applies the factory-freshness rule (issue #79) to a probed verdict.
///
/// - [`Freshness::Fresh`] — proceed, restating that a first flash takes no
///   backup (there is nothing to save).
/// - [`Freshness::SameApplication`] — proceed **without** `--force`: re-flashing
///   the same application is the documented recovery path for an interrupted
///   flash (see `docs/explanation/safety.md`). The notice still says what a
///   re-flash resets.
/// - [`Freshness::Resident`] — a *different* (or unidentifiable) application is
///   loaded (on System 7: a driven load-state machine is not `Loaded`, or the
///   code differs from the product's; a healthy System 7 device arrives as
///   `SameApplication` through [`bussard_download::flash_gate`]). Refused
///   unless `force`, because the flash would destroy it with no backup; the
///   message names the resident application and the two ways forward.
/// - [`Freshness::Mismatch`] — the device is not one this download fits (an
///   association table in a format bussard does not write). Refused unless
///   `force`, before anything is unloaded.
/// - [`Freshness::Unknown`] — the state could not be read. Refused unless
///   `force`: "unreadable" is not evidence of an empty device, and a flash with
///   no backup must not be what finds out.
///
/// `force` proceeds in both refusal cases, with a single loud line that names
/// the device, the gateway and what is being destroyed.
pub fn decide_freshness(
    target: IndividualAddress,
    gateway: &str,
    dir: &Path,
    force: bool,
    freshness: &Freshness,
) -> FreshnessDecision {
    // The one gate (issue #895): the MCP's flash and load ask the same
    // function, without `--force`.
    let refusal = freshness_refusal(target, freshness, force);
    let proceed = refusal.is_none();
    let dir = dir.display();
    let (message, prompt_note) = match freshness {
        Freshness::Fresh => (
            format!(
                "\npre-flight: no application is loaded on {target} — the device is \
                 factory-fresh.\n\n\
                 NOTE: a first flash assumes the device is factory-fresh; no backup is\n\
                 possible (there is no prior application to save). Recovery from a failed\n\
                 flash is re-running `bussard flash`."
            ),
            None,
        ),
        Freshness::SameApplication { resident } => (
            format!(
                "\npre-flight: {target} already runs this application ({resident}).\n\n\
                 NOTE: re-flashing the SAME application is allowed without --force — it is\n\
                 the documented recovery path for an interrupted flash. It is still a full\n\
                 rewrite and takes no backup: the parameters are reset to the vendor\n\
                 defaults plus this model's parameter overrides, and the address,\n\
                 association and group-object tables are rewritten from the model's links."
            ),
            Some(format!(
                "{target} currently has {resident} Loaded; re-flashing the same application \
                 resets its parameters and tables."
            )),
        ),
        Freshness::Resident {
            resident,
            objects,
            reason,
        } => {
            let what = resident_words(resident.as_deref(), reason.as_deref());
            let where_ = objects.join(", ");
            if proceed {
                (
                    format!(
                        "\nWARNING: --force — {target} via {gateway} is NOT factory-fresh: it has \
                         {what} Loaded ({where_}); this flash DESTROYS it, its parameters and its \
                         links, and takes NO backup."
                    ),
                    Some(format!(
                        "{target} currently has {what} Loaded; this flash DESTROYS it (no backup)."
                    )),
                )
            } else {
                (
                    format!(
                        "\nREFUSING to flash {target}: it is not factory-fresh.\n\
                         \x20 resident : {what}\n\
                         \x20 loaded   : {where_}\n\
                         A flash unloads and rewrites the application wholesale and takes NO backup,\n\
                         so this would destroy the resident application, its parameters and its links.\n\
                        \n\
                         Two ways forward:\n\
                         \x20 1. Capture what is on the device first: `bussard reconstruct {target} \
                         --dir {dir}`\n\
                         \x20    writes its links into the model, and `bussard apply {target}` backs \
                         the tables\n\
                         \x20    up to {dir}/captures/backups/ before it writes.\n\
                         \x20 2. Re-run with --force to overwrite it anyway (destructive, no backup).\n\
                        \n\
                         Re-flashing the SAME application needs no --force; this device does not \
                         report it."
                    ),
                    None,
                )
            }
        }
        Freshness::Mismatch { reason } => {
            if proceed {
                (
                    format!(
                        "\nWARNING: --force — {target} via {gateway} does not match this \
                         download: {reason}. Flashing anyway."
                    ),
                    Some(format!("{target} does not match this download ({reason}).")),
                )
            } else {
                (
                    format!(
                        "\nREFUSING to flash {target}: {reason}.\n\
                         Nothing was unloaded or written. Check that the address names the \
                         device the model means,\n\
                         or re-run with --force to flash anyway."
                    ),
                    None,
                )
            }
        }
        Freshness::Unknown { reason } => {
            if proceed {
                (
                    format!(
                        "\nWARNING: --force — bussard could not read whether {target} via \
                         {gateway} is factory-fresh ({reason}); flashing anyway DESTROYS any \
                         application it carries, and takes NO backup."
                    ),
                    Some(format!(
                        "{target}'s load state is unreadable; if it carries an application this \
                         flash DESTROYS it (no backup)."
                    )),
                )
            } else {
                (
                    format!(
                        "\nREFUSING to flash {target}: its load state is unreadable, so bussard \
                         cannot tell\n\
                         whether the device is factory-fresh ({reason}).\n\
                         The device did NOT report an application as Loaded — the state is simply \
                         unknown,\n\
                         and a flash that takes no backup must not be what finds out.\n\
                         Re-run once the device answers reliably, or with --force to flash anyway \
                         (destructive\n\
                         if it carries an application)."
                    ),
                    None,
                )
            }
        }
    };
    FreshnessDecision {
        message,
        proceed,
        refusal,
        prompt_note,
    }
}

/// The factory-freshness gate of a flash (issue #79) in one sentence: why
/// the flash must not run, `None` when it may. The one gate both surfaces
/// ask (issue #895): `bussard flash` through [`decide_freshness`] with its
/// `--force`, the MCP tier's flash and application load with `force` false,
/// since a chat cannot pass `--force`.
///
/// A factory-fresh device and one that runs this application pass. A device
/// that runs another application (identified, or a System 7 code sample that
/// differs, or one whose id cannot be read), one that does not fit the
/// download, and one whose state could not be read are refused unless
/// `force`: a flash takes no backup, so it must not destroy what nobody
/// agreed to destroy.
pub fn freshness_refusal(
    target: IndividualAddress,
    gate: &Freshness,
    force: bool,
) -> Option<String> {
    if force {
        return None;
    }
    match gate {
        Freshness::Fresh | Freshness::SameApplication { .. } => None,
        Freshness::Resident {
            resident, reason, ..
        } => Some(format!(
            "{target} runs {}, which a flash destroys with no backup; replacing it is `bussard \
             flash --force {target}` at the CLI",
            resident_words(resident.as_deref(), reason.as_deref())
        )),
        Freshness::Mismatch { reason } => Some(format!(
            "{target} does not match this download: {reason}; nothing was written"
        )),
        Freshness::Unknown { reason } => Some(format!(
            "{target}'s resident application could not be confirmed ({reason}), so a flash \
             cannot tell what it replaces; check the device and plan again"
        )),
    }
}

/// Whether a plan can name what a flash of this verdict replaces: the device
/// runs another application whose id was read, or (System 7) whose code
/// sample says what differs. The MCP tier's application load (issue #750)
/// names it in the plan's sentences, so the human's yes to that plan's
/// digest is the chat's `--force` for [`freshness_refusal`]; a device that
/// does not fit the download, whose state is unknown or whose application
/// cannot be identified gives a plan nothing to name, and stays refused.
pub fn names_replacement(gate: &Freshness) -> bool {
    matches!(
        gate,
        Freshness::Resident {
            resident: Some(_),
            ..
        } | Freshness::Resident {
            reason: Some(_),
            ..
        }
    )
}

/// What a flash finds on the device, in one line: the gate's verdict as a
/// plan states it.
pub fn freshness_line(gate: &Freshness) -> String {
    match gate {
        Freshness::Fresh => "no application is loaded (factory-fresh)".to_string(),
        Freshness::SameApplication { resident } => {
            format!("runs this application ({resident})")
        }
        Freshness::Resident {
            resident, reason, ..
        } => format!(
            "runs {}",
            resident_words(resident.as_deref(), reason.as_deref())
        ),
        Freshness::Mismatch { reason } => format!("does not match this download ({reason})"),
        Freshness::Unknown { reason } => format!("unknown ({reason})"),
    }
}

/// The resident application of a [`Freshness::Resident`] verdict in words.
fn resident_words(resident: Option<&str>, reason: Option<&str>) -> String {
    match (resident, reason) {
        (Some(id), _) => format!("application {id}"),
        // System 7 (issue #314): the code sample says what differs.
        (None, Some(reason)) => format!("another application ({reason})"),
        (None, None) => {
            "an application bussard could not identify (no readable PID_PROGRAM_VERSION)"
                .to_string()
        }
    }
}

/// The parameter-level plan of a flash (issue #109): what it changes in the
/// vendor's own words. System 7 writes whole memory regions, so its plan is
/// the memory-level one and this carries only the note. `skipped_for_force`
/// replaces the "could not be read" note when `--force` did not read the
/// device's values.
pub fn parameter_plan(
    app: &ApplicationProgram,
    inputs: &FlashInputs<'_>,
    plan: &FlashPlan,
    current: &CurrentMemory,
    skipped_for_force: bool,
) -> ParamPlan {
    let mut params = if plan.is_sys7() {
        ParamPlan {
            note: Some(bussard_download::SYS7_NOTE.to_string()),
            ..Default::default()
        }
    } else {
        bussard_download::param_plan(app, inputs.overrides(), inputs.base_offsets(), current)
    };
    if skipped_for_force {
        params.note = Some(FORCE_SKIPS_READBACK_NOTE.to_string());
    }
    params
}

/// What the read-back after a flash compares against (issue #349): the
/// product and application the image came from, the model and the device's
/// mask as the pre-flight read it.
pub struct ReadbackInputs<'a> {
    /// The product data the image was built from.
    pub product: &'a ProductData,
    /// The application program flashed.
    pub app: &'a ApplicationProgram,
    /// The model the image was built from.
    pub model: Option<&'a Model>,
    /// The device's mask, as the pre-flight read it.
    pub device_mask: u16,
}

/// How a flash ended: the download's outcome and the independent read-back
/// made on its last connection.
pub struct Flashed {
    /// The download, its restart and its load-state verification.
    pub outcome: Result<FlashOutcome, WriteError>,
    /// The read-back of the tables, the group-object count, the parameters
    /// and the security object (issues #319, #349); `None` when the download
    /// failed before it could run or no read-back was asked for.
    pub readback: Option<WriteReadback>,
}

impl Flashed {
    /// Whether the download verified and the read-back found nothing that
    /// differs from the model. A flash that reports a loaded application
    /// while the device does not hold the model is not verified (a silent
    /// success is a P1).
    pub fn verified(&self) -> bool {
        matches!(&self.outcome, Ok(o) if o.ok()) && self.failure().is_none()
    }

    /// What the read-back found differing from the model, in one sentence.
    pub fn failure(&self) -> Option<String> {
        self.readback.as_ref().and_then(WriteReadback::failure)
    }
}

/// Runs the download of `plan`, then the independent read-back on its last
/// connection (the one the post-restart verification ran on), comparing the
/// device with what `expected` names. `None` skips the read-back (a plan
/// whose product data is gone); [`Flashed::verified`] then rests on the
/// download alone.
pub async fn flash_and_verify(
    run: FlashRun<'_>,
    plan: &FlashPlan,
    observer: &mut impl FlashObserver,
    expected: Option<ReadbackInputs<'_>>,
    target: IndividualAddress,
) -> Flashed {
    let (outcome, readback) = crate::download::flash_session(run, plan, observer, async |l4| {
        let rb = expected?;
        let expected =
            Expected::for_flash(plan, rb.product, rb.app, rb.model, target, rb.device_mask);
        Some(crate::verify::read_back(l4, &expected).await)
    })
    .await;
    Flashed {
        outcome,
        readback: readback.flatten(),
    }
}

/// What a verified flash recorded in `bussard.lock`: the security
/// individual address table it wrote (PID 54, issue #297) and the
/// group-object security flags (PID 61, issue #331). `None` where the flash
/// wrote no such table; `Err` carries why the record failed.
#[derive(Debug, Default)]
pub struct LockRecord {
    /// The PID 54 record: whether the lock changed, and how many senders.
    pub senders: Option<(Result<bool, String>, usize)>,
    /// The PID 61 record: whether the lock changed, and how many objects.
    pub flags: Option<(Result<bool, String>, usize)>,
}

/// Records in the lock what a verified flash wrote to the security object,
/// as `adopt` does: `senders` is the PID 54 table the plan wrote (from
/// [`FlashInputs::finish`]). Only a secured download writes one.
pub fn record_lock(
    dir: &Path,
    target: IndividualAddress,
    senders: Option<&[SecureSenderEntry]>,
    plan: &FlashPlan,
) -> LockRecord {
    let Some(senders) = senders else {
        return LockRecord::default();
    };
    let recorded = crate::admission::record_secure_senders(dir, target, senders)
        .map_err(|err| err.to_string());
    let flags = crate::security_change::flash_secured_objects(plan).map(|objects| {
        (
            crate::security_change::record_security_flags(dir, target, &objects)
                .map_err(|err| err.to_string()),
            objects.len(),
        )
    });
    LockRecord {
        senders: Some((recorded, senders.len())),
        flags,
    }
}

/// Whether a download loads load-state machine `lsm` (1 address table, 2
/// association table, 3 group-object table on System B; LSM 1 holds the
/// address and group-object tables on System 7).
pub fn loads_lsm(plan: &FlashPlan, lsm: u32) -> bool {
    plan.steps.iter().any(|s| match s {
        bussard_download::FlashStep::StartLoading { target: Some(t) } => *t == lsm,
        bussard_download::FlashStep::Sys7StartLoading { lsm: l } => *l == lsm,
        _ => false,
    })
}

/// Whether a download writes the link tables (the address and the
/// association table). A self-contained single-object download does not: it
/// leaves them as the device holds them.
pub fn loads_link_tables(plan: &FlashPlan) -> bool {
    loads_lsm(plan, 1) && loads_lsm(plan, 2)
}

/// The recovery advice after a failed first flash.
pub fn recovery_text(target: IndividualAddress) -> String {
    format!(
        "\nThe device may be left with a partially-written or unloaded application.\n\
         Because this was a first flash there is no prior state to restore.\n\
         Recover by re-running `bussard flash {target}` (the download is idempotent —\n\
         it re-unloads and rewrites the application wholesale), or by downloading the\n\
         device with ETS. Do not assume the device is functional until a re-flash\n\
         reports the application is Loaded and verified.",
    )
}

/// Why the application program bussard.lock pins must be loaded into a
/// device before the model can be written to it, in one sentence; `None`
/// when the device runs it.
///
/// `check` is the identity verdict against the lock (another mask or
/// application id is drift), `gate` the factory-freshness verdict of the
/// probe against the pinned application ([`bussard_download::flash_gate`]):
/// a device with no application loaded, or with the pinned one not
/// `Loaded`, needs the load too.
pub fn load_reason(
    target: IndividualAddress,
    check: Option<&IdentityCheck>,
    gate: &Freshness,
    resident: &ResidentState,
    expected: &str,
) -> Option<String> {
    if let Some(check) = check.filter(|c| c.is_drift()) {
        return Some(format!(
            "{target} does not run the application program bussard.lock pins ({expected}): {}",
            check.differences.join("; ")
        ));
    }
    match gate {
        Freshness::Fresh => Some(format!(
            "{target} has no application program loaded; {expected} must be loaded first"
        )),
        Freshness::Resident {
            resident: Some(id), ..
        } => Some(format!(
            "{target} runs application {id}, not {expected} which bussard.lock pins"
        )),
        Freshness::Resident {
            reason: Some(reason),
            ..
        } => Some(format!(
            "{target} does not run the application program bussard.lock pins ({expected}): \
             {reason}"
        )),
        Freshness::SameApplication { .. } if !resident.has_loaded_application() => Some(format!(
            "{target} holds {expected} but it is not loaded (an interrupted download); it must \
             be loaded again"
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok("1.1.7".parse()?)
    }

    fn loaded() -> ResidentState {
        ResidentState {
            objects: vec![bussard_download::ResidentObject {
                index: 4,
                object_type: Some(3),
                state: bussard_mgmt::LoadState::Loaded,
            }],
            ..ResidentState::default()
        }
    }

    #[test]
    fn test_load_reason_fresh_device_needs_the_load() -> Result<(), Box<dyn std::error::Error>> {
        let why = load_reason(
            target()?,
            None,
            &Freshness::Fresh,
            &ResidentState::default(),
            "M-00FA_A-0002-01",
        );
        assert!(
            why.as_deref()
                .is_some_and(|w| w.contains("no application program loaded")),
            "{why:?}"
        );
        Ok(())
    }

    #[test]
    fn test_load_reason_same_loaded_application_needs_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let gate = Freshness::SameApplication {
            resident: "M-00FA A-0002 v1".to_string(),
        };
        assert_eq!(
            load_reason(target()?, None, &gate, &loaded(), "M-00FA_A-0002-01"),
            None
        );
        Ok(())
    }

    #[test]
    fn test_load_reason_other_application_names_it() -> Result<(), Box<dyn std::error::Error>> {
        let gate = Freshness::Resident {
            resident: Some("M-0083 A-0007 v35".to_string()),
            objects: Vec::new(),
            reason: None,
        };
        let why = load_reason(target()?, None, &gate, &loaded(), "M-00FA_A-0002-01");
        assert!(
            why.as_deref().is_some_and(|w| w.contains("M-0083 A-0007")),
            "{why:?}"
        );
        Ok(())
    }

    #[test]
    fn test_freshness_refusal_refuses_every_resident_application_without_force()
    -> Result<(), Box<dyn std::error::Error>> {
        let identified = Freshness::Resident {
            resident: Some("M-0083 A-0007 v35".to_string()),
            objects: Vec::new(),
            reason: None,
        };
        let sys7 = Freshness::Resident {
            resident: None,
            objects: Vec::new(),
            reason: Some("the code differs at 0x4000".to_string()),
        };
        let unidentified = Freshness::Resident {
            resident: None,
            objects: Vec::new(),
            reason: None,
        };
        let unknown = Freshness::Unknown {
            reason: "no answer".to_string(),
        };
        let mismatch = Freshness::Mismatch {
            reason: "another table format".to_string(),
        };
        for gate in [&identified, &sys7, &unidentified, &unknown, &mismatch] {
            let refusal = freshness_refusal(target()?, gate, false);
            assert!(refusal.is_some(), "{gate:?}");
            assert_eq!(freshness_refusal(target()?, gate, true), None, "{gate:?}");
            // The CLI's decision is the same gate.
            let decision = decide_freshness(target()?, "gw", Path::new("knx"), false, gate);
            assert!(!decision.proceed);
            assert_eq!(decision.refusal, refusal);
            let forced = decide_freshness(target()?, "gw", Path::new("knx"), true, gate);
            assert!(forced.proceed && forced.refusal.is_none());
        }
        let names = freshness_refusal(target()?, &identified, false).unwrap_or_default();
        assert!(names.contains("M-0083 A-0007 v35"), "{names}");
        assert!(names.contains("bussard flash --force 1.1.7"), "{names}");
        Ok(())
    }

    #[test]
    fn test_names_replacement_only_for_an_identified_application() {
        let identified = Freshness::Resident {
            resident: Some("M-0083 A-0007 v35".to_string()),
            objects: Vec::new(),
            reason: None,
        };
        let sys7 = Freshness::Resident {
            resident: None,
            objects: Vec::new(),
            reason: Some("the code differs".to_string()),
        };
        let unidentified = Freshness::Resident {
            resident: None,
            objects: Vec::new(),
            reason: None,
        };
        assert!(names_replacement(&identified) && names_replacement(&sys7));
        assert!(!names_replacement(&unidentified));
        assert!(!names_replacement(&Freshness::Unknown {
            reason: "x".to_string()
        }));
        assert!(!names_replacement(&Freshness::Mismatch {
            reason: "x".to_string()
        }));
    }

    #[test]
    fn test_freshness_refusal_passes_fresh_and_same_application()
    -> Result<(), Box<dyn std::error::Error>> {
        let same = Freshness::SameApplication {
            resident: "M-00FA A-0002 v1".to_string(),
        };
        for gate in [&Freshness::Fresh, &same] {
            assert_eq!(freshness_refusal(target()?, gate, false), None);
            let decision = decide_freshness(target()?, "gw", Path::new("knx"), false, gate);
            assert!(decision.proceed && decision.refusal.is_none());
        }
        Ok(())
    }
}
