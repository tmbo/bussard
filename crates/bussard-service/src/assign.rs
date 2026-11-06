//! The assign flow (issue #749): give the one device in programming mode an
//! individual address, as `bussard assign` does and as the first half of
//! `bussard adopt` and `knx_add_device`.
//!
//! The steps, in the order a surface runs them:
//!
//! 1. [`target_address`]: the explicit address checked against the model, or
//!    the next free one on the model's busiest line.
//! 2. [`probe_occupant`]: step 1 of NM_IndividualAddress_Write (Management
//!    Procedures 03_05_02 §2.3, issue #530): nothing may answer at the target.
//! 3. [`wait_for_programming_mode`]: the programming-mode broadcast, repeated
//!    for up to [`PROGRAMMING_WAIT_TOTAL`] until exactly one device answers.
//! 4. [`identify`]: what the device in programming mode is (mask, serial,
//!    manufacturer, order number), read at its current address.
//! 5. [`write_address`]: the `A_IndividualAddress_Write` broadcast.
//! 6. [`verify_assignment_with`]: the independent read-back at the new address,
//!    with the explicit programming-mode clear ETS does.
//! 7. [`still_in_programming_mode`]: the broadcast once more, briefly; a device
//!    that still answers it would be re-captured by the next assign.
//! 8. [`write_device_file`]: the device file and its lock entry (serial, #752).
//!
//! Nothing here prints or asks. The CLI keeps its prompts and lines, the MCP
//! tool its questions and JSON; both call these functions (#314).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bussard_mgmt::{MgmtError, broadcast, manufacturers, system_type};
use bussard_model::schema::{Device, Product};
use bussard_model::{IndividualAddress, LoadedDevice, Model};
use bussard_secure::{Key16, SequenceHighWater};

use crate::identity::{Identity, SecureStatus, read_identity, read_manufacturer, read_order};
use crate::secure::ToolKeys;
use crate::{Authorize, BusService, L4Options, Management, ServiceError, SourcePolicy};

/// The line to allocate on when the model has no devices to infer one from.
pub const FALLBACK_LINE: (u8, u8) = (1, 1);

/// Total time to wait for a device to enter programming mode before giving up.
pub const PROGRAMMING_WAIT_TOTAL: Duration = Duration::from_secs(30);

/// The initial polling budget before the surface reminds the human to press
/// the programming button.
pub const INITIAL_POLL_TOTAL: Duration = Duration::from_secs(3);

/// Environment variable that shortens the programming-mode wait windows. Set by
/// the integration tests so both the outer poll budgets (reminder / total)
/// and the per-poll response-collection window shrink together; unset in normal
/// use so the full [`PROGRAMMING_WAIT_TOTAL`] and default collection window
/// apply. Behaviour is unchanged without the variable.
pub const WAIT_MS_ENV: &str = "BUSSARD_ASSIGN_WAIT_MS";

/// Why an assign step failed.
#[derive(Debug, thiserror::Error)]
pub enum AssignError {
    /// The address or the model refuses the assignment; the sentence says why.
    #[error("{0}")]
    Refused(String),
    /// A bus session or lease failed.
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// A broadcast failed.
    #[error(transparent)]
    Mgmt(#[from] MgmtError),
    /// The device file or the lock could not be saved.
    #[error("saving the {what} to {dir}")]
    Save {
        /// What was saved ("stub device file", "device file").
        what: String,
        /// The model directory.
        dir: String,
        /// The cause.
        #[source]
        source: bussard_model::SaveError,
    },
}

/// Reads [`WAIT_MS_ENV`] as a millisecond budget, if set and parseable.
fn wait_ms_override() -> Option<Duration> {
    bussard_model::dotenv::var(WAIT_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// The (reminder, total) wait budgets, honouring [`WAIT_MS_ENV`] for tests.
/// With the override set, the reminder budget scales to half the total so
/// [`INITIAL_POLL_TOTAL`] is gated under the same variable as the total.
pub fn wait_budgets() -> (Duration, Duration) {
    match wait_ms_override() {
        Some(total) => (total / 2, total),
        None => (INITIAL_POLL_TOTAL, PROGRAMMING_WAIT_TOTAL),
    }
}

/// The per-poll response-collection window, honouring [`WAIT_MS_ENV`] for tests.
/// Without the override the mgmt default
/// ([`broadcast::PROGRAMMING_MODE_WINDOW`]) applies.
pub fn collection_window() -> Duration {
    wait_ms_override().unwrap_or(broadcast::PROGRAMMING_MODE_WINDOW)
}

// ---------------------------------------------------------------------------
// Step 1: the target address
// ---------------------------------------------------------------------------

/// The target address: `explicit` checked against the model
/// ([`validate_explicit_address`]), else the next free one
/// ([`allocate_address`]). `hint` ends the refusal when nothing can be
/// allocated (the surface's way to pass an address).
///
/// # Errors
///
/// The explicit address is invalid or taken, or nothing can be allocated.
pub fn target_address(
    explicit: Option<&str>,
    model: Option<&Model>,
    hint: &str,
) -> Result<IndividualAddress, AssignError> {
    match explicit {
        Some(s) => validate_explicit_address(s, model),
        None => allocate_address(model).ok_or_else(|| {
            AssignError::Refused(format!(
                "could not allocate a free address automatically; {hint}"
            ))
        }),
    }
}

/// Validates an explicit address against the model.
///
/// Checks: it parses as an individual address; it is not already used by a model
/// device; and, when a model is present, it sits on a line the model already
/// uses (assigning onto an unmodeled line is almost always a typo).
///
/// # Errors
///
/// One of the checks fails; the sentence says which.
pub fn validate_explicit_address(
    s: &str,
    model: Option<&Model>,
) -> Result<IndividualAddress, AssignError> {
    let addr: IndividualAddress = s.parse().map_err(|err| {
        AssignError::Refused(format!(
            "invalid address {s:?}; expected area.line.device like \"1.1.47\": {err}"
        ))
    })?;

    if let Some(model) = model {
        if let Some(existing) = model.devices.get(&addr) {
            return Err(AssignError::Refused(format!(
                "address {addr} is already used in your project (\"{}\"); pick a free one",
                existing.device.name
            )));
        }
        let lines = model_lines(model);
        if !lines.is_empty() && !lines.contains(&(addr.area(), addr.line())) {
            let known: Vec<String> = lines.iter().map(|(a, l)| format!("{a}.{l}")).collect();
            return Err(AssignError::Refused(format!(
                "address {addr} is on line {}.{}, which the model does not use (known lines: {}); \
                 double-check the address",
                addr.area(),
                addr.line(),
                known.join(", ")
            )));
        }
    }
    Ok(addr)
}

/// Allocates the lowest free device number on the model's dominant line.
///
/// Returns `None` only when there is no model at all (the caller then requires
/// an explicit address).
pub fn allocate_address(model: Option<&Model>) -> Option<IndividualAddress> {
    let model = model?;
    let (area, line) = dominant_line(model).unwrap_or(FALLBACK_LINE);
    let used = used_devices_on_line(model, area, line);
    allocate_on_line(area, line, &used)
}

/// Picks the lowest unused device number ≥ 1 on `area.line`. Device 0 is the
/// line/coupler address. `None` if the line is full.
fn allocate_on_line(area: u8, line: u8, used: &BTreeSet<u8>) -> Option<IndividualAddress> {
    (1u8..=255)
        .find(|d| !used.contains(d))
        .and_then(|d| IndividualAddress::new(area, line, d).ok())
}

/// The device numbers already spoken for on `area.line`.
fn used_devices_on_line(model: &Model, area: u8, line: u8) -> BTreeSet<u8> {
    model
        .devices
        .keys()
        .filter(|ia| ia.area() == area && ia.line() == line)
        .map(|ia| ia.device())
        .collect()
}

/// The model's dominant line: the `(area, line)` with the most devices, ties
/// broken by the lowest `(area, line)`. `None` when the model has no devices.
fn dominant_line(model: &Model) -> Option<(u8, u8)> {
    let mut counts: BTreeMap<(u8, u8), usize> = BTreeMap::new();
    for ia in model.devices.keys() {
        *counts.entry((ia.area(), ia.line())).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(line, count)| (count, std::cmp::Reverse(line)))
        .map(|(line, _)| line)
}

/// The set of distinct `(area, line)` pairs the model uses.
fn model_lines(model: &Model) -> BTreeSet<(u8, u8)> {
    model
        .devices
        .keys()
        .map(|ia| (ia.area(), ia.line()))
        .collect()
}

// ---------------------------------------------------------------------------
// Step 2: the occupant check
// ---------------------------------------------------------------------------

/// What answers at an address bussard is about to give a device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Occupant {
    /// The mask version, `None` when the device closed the connection
    /// instead of answering the descriptor read (occupied all the same).
    pub mask: Option<u16>,
    /// The KNX manufacturer id, when readable.
    pub manufacturer_id: Option<u16>,
    /// The order info string, when readable.
    pub order: Option<String>,
}

impl Occupant {
    /// One line naming what answered: mask, system, manufacturer, order number.
    pub fn describe(&self) -> String {
        let mut parts = vec![match self.mask {
            Some(mask) => format!("mask {mask:04X}, {}", system_type(mask)),
            None => "it closed the connection instead of answering".to_string(),
        }];
        if let Some(id) = self.manufacturer_id {
            parts.push(format!("manufacturer {}", manufacturers::display(id)));
        }
        if let Some(order) = &self.order {
            parts.push(format!("order number {order:?}"));
        }
        parts.join(", ")
    }
}

/// Step 1 of NM_IndividualAddress_Write (Management Procedures 03_05_02
/// §2.3, issue #530): connects to `target` and reads its device descriptor.
/// Any answer means the address is taken, and so does a `T_Disconnect` in
/// reply; silence means it is free (`None`). An answering device is asked
/// for its manufacturer and order number too, best-effort, so the refusal
/// can name it. `replace`, `assign`, `adopt`, `commission` and
/// `knx_add_device` share this.
pub async fn probe_occupant(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
) -> Option<Occupant> {
    let options = L4Options {
        source: SourcePolicy::Known(source),
        timeouts: crate::scan::discovery_timeouts(),
        authorize: Authorize::Skip,
        ..L4Options::default()
    };
    service
        .with_l4(target, &options, async |dev| {
            let mask = match bussard_mgmt::read_device_descriptor(dev).await {
                Ok(mask) => mask,
                Err(MgmtError::Disconnected { .. }) => {
                    return Ok::<_, ServiceError>(Some(Occupant::default()));
                }
                Err(_) => return Ok(None),
            };
            let manufacturer_id = read_manufacturer(dev).await;
            let order = read_order(dev).await;
            Ok(Some(Occupant {
                mask: Some(mask),
                manufacturer_id,
                order,
            }))
        })
        .await
        .ok()
        .flatten()
}

/// The refusal sentence for an occupied `target`; `verb` is the command
/// to re-run with `--force`.
pub fn occupied_refusal(target: IndividualAddress, occupant: &Occupant, verb: &str) -> String {
    format!(
        "{target} is already in use: a device answers there ({}). Two devices on one \
         address answer the same connection, so a later write can land on the wrong one. \
         Pick a free address, or remove or re-address that device first; if you mean to give \
         {target} to the device in programming mode anyway, re-run `bussard {verb}` with \
         --force. Nothing was written.",
        occupant.describe()
    )
}

// ---------------------------------------------------------------------------
// Step 3: the wait for the programming button
// ---------------------------------------------------------------------------

/// What the programming-mode wait found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgrammingWait {
    /// Exactly one device answered, at this (current) address.
    One(IndividualAddress),
    /// Several devices are in programming mode; the flow works on one.
    Several(Vec<IndividualAddress>),
    /// Nothing answered within the budget.
    Nothing {
        /// The budget waited.
        waited: Duration,
    },
}

/// What happens while [`wait_for_programming_mode`] waits, for the surface
/// to tell the human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitEvent {
    /// The first polls found nothing: time to remind the human to press the
    /// programming button (sent once).
    Remind,
    /// Still waiting after the reminder, with this much budget left.
    Waiting {
        /// The budget left.
        remaining: Duration,
    },
}

/// Polls for devices in programming mode until exactly one answers, several
/// answer, or the budget ([`wait_budgets`]) is spent. `on_event` hears the
/// reminder and the countdown.
///
/// # Errors
///
/// The bus could not be leased or the broadcast failed.
pub async fn wait_for_programming_mode(
    service: &BusService,
    source: IndividualAddress,
    on_event: &mut (dyn FnMut(WaitEvent) + Send),
) -> Result<ProgrammingWait, AssignError> {
    let (initial, total) = wait_budgets();
    let start = tokio::time::Instant::now();
    let mut reminded = false;
    let window = collection_window();
    loop {
        // Lease a fresh channel for this broadcast read (released each poll).
        let channel = service.lease_channel().await?;
        let found = broadcast::devices_in_programming_mode(channel, source, window).await?;
        match found.len() {
            1 => return Ok(ProgrammingWait::One(found[0])),
            n if n > 1 => return Ok(ProgrammingWait::Several(found)),
            _ => {}
        }
        let elapsed = start.elapsed();
        if elapsed >= total {
            return Ok(ProgrammingWait::Nothing { waited: total });
        }
        if elapsed >= initial && !reminded {
            on_event(WaitEvent::Remind);
            reminded = true;
        }
        if reminded {
            on_event(WaitEvent::Waiting {
                remaining: total.saturating_sub(elapsed),
            });
        }
    }
}

/// The devices in programming mode now: one broadcast, one collection window.
///
/// # Errors
///
/// The bus could not be leased or the broadcast failed.
pub async fn in_programming_mode(
    service: &BusService,
    source: IndividualAddress,
) -> Result<Vec<IndividualAddress>, AssignError> {
    let channel = service.lease_channel().await?;
    Ok(broadcast::devices_in_programming_mode(channel, source, collection_window()).await?)
}

// ---------------------------------------------------------------------------
// Steps 4 to 6: identify, write, verify
// ---------------------------------------------------------------------------

/// What a read of the device returned: before the write ([`identify`]) or
/// after it ([`verify_assignment_with`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verified {
    /// The mask version read back from the device.
    pub mask: Option<u16>,
    /// The KNX manufacturer id, when readable.
    pub manufacturer_id: Option<u16>,
    /// The device serial number, when readable.
    pub serial: Option<Vec<u8>>,
    /// The device's order info string, when readable.
    pub order: Option<String>,
    /// Whether the explicit `PID_PROGMODE = 0` write to clear programming mode was
    /// confirmed by the device. `false` when the write was not confirmed, refused
    /// or not asked for: the broadcast-based check then remains the fallback.
    pub programming_mode_cleared: bool,
    /// How the device was read with respect to KNX Data Secure
    /// (issue #203). With [`SecureStatus::ActivatedNoKey`] the mask is `None`:
    /// the plain read only returned the hidden `FFFF`.
    pub secure: SecureStatus,
    /// Warnings the read raised, for the surface to say (the keyring's tool
    /// key did not open the device but a plain read did).
    pub warnings: Vec<String>,
}

/// The tool key for the read-back of a Data Secure-activated device
/// (issue #203).
#[derive(Debug, Clone, Default)]
pub struct VerifyKey {
    /// The tool key, or `None` to verify in the clear.
    pub tool_key: Option<Key16>,
    /// The key came from the keyring entry of the OLD address: the keyring must
    /// be re-exported after the address change.
    pub from_old_address: bool,
}

impl VerifyKey {
    /// Picks the key for a device moving from `current` to `target`: a raw
    /// tool key wins; else the keyring entry of `target`; else the entry of
    /// `current` (flagged, since the keyring is then stale); else none.
    pub fn resolve(
        keys: &ToolKeys,
        current: IndividualAddress,
        target: IndividualAddress,
    ) -> VerifyKey {
        if keys.raw_given() || keys.lists(target) {
            return VerifyKey {
                tool_key: keys.tool_key(target),
                from_old_address: false,
            };
        }
        if keys.lists(current) {
            return VerifyKey {
                tool_key: keys.tool_key(current),
                from_old_address: true,
            };
        }
        VerifyKey::default()
    }
}

/// Why the read-back after a write failed.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The bus could not be leased: nothing was read.
    #[error(transparent)]
    Lease(ServiceError),
    /// The device did not answer at the new address as it should; the
    /// sentence says what was seen and that the assignment is unverified.
    #[error("{0}")]
    Unverified(String),
}

/// Reads what the device in programming mode is, at its current address,
/// before anything is written: the descriptor, then (authorized with free
/// access, best effort) the manufacturer, serial number and order number.
/// Read-only. With `tool_key` every read rides A_SecureData.
///
/// # Errors
///
/// The device did not answer the descriptor read, or the bus failed.
pub async fn identify(
    service: &BusService,
    source: IndividualAddress,
    address: IndividualAddress,
    tool_key: Option<Key16>,
) -> Result<Verified, ServiceError> {
    let secured = tool_key.is_some();
    let options = L4Options {
        source: SourcePolicy::Known(source),
        authorize: Authorize::Skip,
        tool_key,
        high_water: SequenceHighWater::new(),
        ..L4Options::default()
    };
    service
        .with_l4(address, &options, async |l4| {
            let identity = read_identity(l4, !secured).await?;
            Ok(Verified::read(identity, secured, false))
        })
        .await
}

/// Broadcasts `A_IndividualAddress_Write`: the one device in programming mode
/// takes `target`.
///
/// # Errors
///
/// The bus could not be leased or the broadcast failed.
pub async fn write_address(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
) -> Result<(), AssignError> {
    let channel = service.lease_channel().await?;
    bussard_mgmt::write_individual_address(channel, source, target).await?;
    Ok(())
}

/// Verifies the write by connecting to `target` and reading its descriptor plus
/// best-effort manufacturer/serial/order properties, clearing programming mode
/// as ETS does when `clear_programming_mode` is set (`adopt` passes `false`).
///
/// A device descriptor read is the proof the address took. With a tool key
/// every read rides A_SecureData; without one, a Data Secure-activated device
/// answers mask `FFFF`, which verifies the address but not the mask
/// (issue #203). When the keyring's key does not open the device but a plain
/// read finds a real mask, the plain read stands with a warning.
///
/// # Errors
///
/// The bus could not be leased, or the device did not answer as it should.
pub async fn verify_assignment_with(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    clear_programming_mode: bool,
    key: &VerifyKey,
) -> Result<Verified, VerifyError> {
    let result = verify_session(service, source, target, clear_programming_mode, key).await;
    let Err(secured_err) = result else {
        return result;
    };
    if key.tool_key.is_none() || matches!(secured_err, VerifyError::Lease(_)) {
        return Err(secured_err);
    }
    match verify_session(
        service,
        source,
        target,
        clear_programming_mode,
        &VerifyKey::default(),
    )
    .await
    {
        Ok(mut verified) if verified.secure == SecureStatus::Plain => {
            verified.warnings.push(format!(
                "warning: {target} did not answer the secured read with its keyring tool key but \
                 answers in the clear: it is not Data Secure-activated, or the keyring is stale"
            ));
            Ok(verified)
        }
        _ => Err(secured_err),
    }
}

/// One verification session, secured when `key` carries a tool key.
async fn verify_session(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    clear_programming_mode: bool,
    key: &VerifyKey,
) -> Result<Verified, VerifyError> {
    let secured = key.tool_key.is_some();
    let options = L4Options {
        source: SourcePolicy::Known(source),
        authorize: Authorize::Skip,
        tool_key: key.tool_key.clone(),
        high_water: SequenceHighWater::new(),
        ..L4Options::default()
    };
    let session = service
        .with_l4(target, &options, async |dev| {
            Ok::<_, ServiceError>(read_back(dev, target, clear_programming_mode, secured).await)
        })
        .await;
    match session {
        Ok(verified) => verified,
        Err(err @ ServiceError::Lease(_)) => Err(VerifyError::Lease(err)),
        Err(err) => Err(VerifyError::Unverified(format!(
            "wrote {target} but could not connect to it afterwards ({err}); the address may \
             not have been applied — check the device and re-run"
        ))),
    }
}

/// The read-back half of [`verify_assignment_with`], on the open session.
async fn read_back(
    dev: &mut Management,
    target: IndividualAddress,
    clear_programming_mode: bool,
    secured: bool,
) -> Result<Verified, VerifyError> {
    let identity = read_identity(dev, !secured).await.map_err(|err| {
        VerifyError::Unverified(if secured {
            format!(
                "wrote {target} and connected, but the device did not answer the SECURED \
                 descriptor read ({err}): either the tool key is not this device's, or the \
                 device is not Data Secure-activated (retry without --keyring/--tool-key); the \
                 assignment is unverified"
            )
        } else if matches!(err, MgmtError::Disconnected { .. }) {
            format!(
                "wrote {target} and connected, but the device disconnected on the first read: \
                 typical for devices whose management is gated on a loaded application or a \
                 different medium profile (e.g. KNX Virtual IP-medium `*.ip` devices, which \
                 disconnect on descriptor reads while their `*.tp` siblings answer). The address \
                 was written but could not be verified."
            )
        } else {
            format!(
                "wrote {target} and connected, but the device did not answer a descriptor read \
                 ({err}); the assignment is unverified"
            )
        })
    })?;

    if !secured && identity.mask_hidden() {
        return Ok(Verified::read(identity, secured, false));
    }
    // Explicitly clear programming mode, exactly as ETS does after assigning an
    // address. Best-effort: the broadcast check remains the fallback.
    let programming_mode_cleared = if !clear_programming_mode {
        false
    } else {
        match dev.clear_programming_mode().await {
            Ok(cleared) => cleared,
            Err(err) => {
                tracing::debug!("{target} clear programming mode (PID_PROGMODE=0) failed: {err}");
                false
            }
        }
    };
    Ok(Verified::read(identity, secured, programming_mode_cleared))
}

impl Verified {
    /// The verdict of a [`read_identity`]: a plain read of a hidden mask is
    /// [`SecureStatus::ActivatedNoKey`] with no mask; otherwise the read
    /// fields, secured or plain.
    fn read(identity: Identity, secured: bool, programming_mode_cleared: bool) -> Verified {
        if !secured && identity.mask_hidden() {
            return Verified {
                secure: SecureStatus::ActivatedNoKey,
                ..Verified::default()
            };
        }
        Verified {
            mask: Some(identity.mask),
            manufacturer_id: identity.manufacturer_id,
            serial: identity.serial,
            order: identity.order,
            programming_mode_cleared,
            secure: if secured {
                SecureStatus::Activated
            } else {
                SecureStatus::Plain
            },
            warnings: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Step 7: the programming-mode check
// ---------------------------------------------------------------------------

/// Re-runs the programming-mode broadcast once, briefly, after a successful
/// write and read-back: `true` when `target` still answers it, so the next
/// `assign`/`adopt` would re-capture and re-address it. Best-effort: a bus
/// error while re-checking is `false` (the assignment already succeeded).
pub async fn still_in_programming_mode(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
) -> bool {
    in_programming_mode(service, source)
        .await
        .is_ok_and(|found| found.contains(&target))
}

/// The warning lines for a device still in programming mode after the
/// assignment: what it means, then what to do.
pub fn still_in_programming_mode_warning(target: IndividualAddress) -> [String; 2] {
    [
        format!(
            "warning: {target} is still in programming mode after the assignment. A conformant \
             device leaves programming mode when it takes its new address; this one did not, so \
             the next `assign`/`adopt` would re-capture and re-address it."
        ),
        "  - on KNX Virtual: toggle programming mode off for this device in the GUI.\n  \
         - on real hardware: this usually means a stuck programming button — release it."
            .to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Step 8: the device file
// ---------------------------------------------------------------------------

/// Builds the stub [`Device`] from the verified read-back. Fields that could not
/// be read are left empty; the whole product block is omitted when nothing was
/// readable.
pub fn build_stub_device(address: IndividualAddress, v: &Verified) -> Device {
    let manufacturer = v.manufacturer_id.map(manufacturers::display);
    let order_number = v.order.clone();
    let mask = v.mask.map(|m| format!("{m:#06X}"));

    let product = if manufacturer.is_some() || order_number.is_some() || mask.is_some() {
        Some(Product {
            manufacturer,
            manufacturer_ref: None,
            order_number,
            hardware_ref: None,
            application_ref: None,
            mask,
        })
    } else {
        None
    };

    Device {
        address,
        name: "New device (assign)".to_string(),
        description: None,
        location: None,
        replaced: None,
        product,
        channels: Default::default(),
        parameters: Default::default(),
        module_bases: Default::default(),
        com_objects: Default::default(),
        // KNX Secure state comes only from the knxproj importer (issue #71).
        security: None,
        application_override: None,
        knxnet: None,
        lock: Default::default(),
    }
}

/// Inserts `device` into the model (or a fresh one) and saves it without
/// pruning. `serial`, the serial number the device reported, goes into its
/// lock entry and off any other device's (issue #752). `what` names the file
/// in the error. Returns the path of the device file that was written.
///
/// # Errors
///
/// The model could not be saved.
pub fn write_device_file(
    model: Option<&Model>,
    dir: &Path,
    device: Device,
    serial: Option<&[u8]>,
    what: &str,
) -> Result<PathBuf, AssignError> {
    let address = device.address;
    let file_stem = device_file_stem(&device);

    let mut model = model.cloned().unwrap_or_else(empty_model);
    model.devices.insert(
        address,
        LoadedDevice {
            device,
            file_stem: file_stem.clone(),
        },
    );
    if let Some(serial) = serial.and_then(|s| <[u8; 6]>::try_from(s).ok()) {
        model.record_serial(address, &serial);
    }
    model.save(dir).map_err(|source| AssignError::Save {
        what: what.to_string(),
        dir: dir.display().to_string(),
        source,
    })?;

    Ok(dir.join("devices").join(format!("{file_stem}.toml")))
}

/// The file stem of a device file: its individual address
/// (`devices/1.1.47.toml`).
pub fn device_file_stem(device: &Device) -> String {
    device.address.to_string()
}

/// An empty model with default config (assigning into a directory that has
/// no model yet).
pub fn empty_model() -> Model {
    Model {
        config: Default::default(),
        groups: Default::default(),
        links: Default::default(),
        devices: Default::default(),
    }
}

/// Formats a byte slice as lowercase hex.
pub use bussard_model::text::hex;

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn model_with(addrs: &[&str]) -> Result<Model, Box<dyn std::error::Error>> {
        let mut model = empty_model();
        for s in addrs {
            let addr: IndividualAddress = s.parse()?;
            let mut device = build_stub_device(addr, &Verified::default());
            device.name = "d".to_string();
            model.devices.insert(
                addr,
                LoadedDevice {
                    device,
                    file_stem: addr.to_string(),
                },
            );
        }
        Ok(model)
    }

    #[test]
    fn test_allocate_address_picks_lowest_free_on_dominant_line() -> TestResult {
        let model = model_with(&["1.1.1", "1.1.2", "1.1.4"])?;
        assert_eq!(allocate_address(Some(&model)), Some("1.1.3".parse()?));
        Ok(())
    }

    #[test]
    fn test_allocate_address_starts_at_one_not_zero() -> TestResult {
        let model = model_with(&["1.1.5"])?;
        assert_eq!(allocate_address(Some(&model)), Some("1.1.1".parse()?));
        Ok(())
    }

    #[test]
    fn test_dominant_line_is_the_busiest() -> TestResult {
        let model = model_with(&["1.1.1", "2.4.1", "2.4.9"])?;
        assert_eq!(dominant_line(&model), Some((2, 4)));
        assert_eq!(allocate_address(Some(&model)), Some("2.4.2".parse()?));
        Ok(())
    }

    #[test]
    fn test_dominant_line_ties_pick_lowest() -> TestResult {
        let model = model_with(&["1.1.1", "2.2.1"])?;
        assert_eq!(dominant_line(&model), Some((1, 1)));
        Ok(())
    }

    #[test]
    fn test_allocate_address_empty_model_falls_back_to_one_one() -> TestResult {
        let model = empty_model();
        assert_eq!(dominant_line(&model), None);
        assert_eq!(allocate_address(Some(&model)), Some("1.1.1".parse()?));
        Ok(())
    }

    #[test]
    fn test_allocate_address_without_model_is_none() {
        assert_eq!(allocate_address(None), None);
    }

    #[test]
    fn test_allocate_on_line_skips_used_and_full_is_none() -> TestResult {
        let used: BTreeSet<u8> = [1, 2, 3, 5].into_iter().collect();
        assert_eq!(allocate_on_line(1, 1, &used), Some("1.1.4".parse()?));
        let full: BTreeSet<u8> = (1u8..=255).collect();
        assert_eq!(allocate_on_line(1, 1, &full), None);
        Ok(())
    }

    #[test]
    fn test_validate_explicit_address_refusals_and_acceptance() -> TestResult {
        let model = model_with(&["1.1.1"])?;
        let taken = validate_explicit_address("1.1.1", Some(&model))
            .err()
            .ok_or("a used address must be refused")?;
        assert!(taken.to_string().contains("already used"), "{taken}");
        let other_line = validate_explicit_address("2.2.5", Some(&model))
            .err()
            .ok_or("an unmodelled line must be refused")?;
        assert!(
            other_line.to_string().contains("does not use"),
            "{other_line}"
        );
        assert_eq!(
            validate_explicit_address("1.1.9", Some(&model))?,
            "1.1.9".parse()?
        );
        assert_eq!(validate_explicit_address("3.4.5", None)?, "3.4.5".parse()?);
        assert!(validate_explicit_address("not-an-address", None).is_err());
        Ok(())
    }

    #[test]
    fn test_build_stub_device_omits_empty_product_and_carries_readable_one() -> TestResult {
        let dev = build_stub_device("1.1.7".parse()?, &Verified::default());
        assert!(dev.product.is_none());
        assert_eq!(dev.name, "New device (assign)");
        assert_eq!(device_file_stem(&dev), "1.1.7");
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            order: Some("MDT-JAL0410".to_string()),
            ..Verified::default()
        };
        let product = build_stub_device("1.1.7".parse()?, &v)
            .product
            .ok_or("expected a product")?;
        assert_eq!(product.manufacturer.as_deref(), Some("MDT"));
        assert_eq!(product.order_number.as_deref(), Some("MDT-JAL0410"));
        assert_eq!(product.mask.as_deref(), Some("0x07B0"));
        Ok(())
    }
}
