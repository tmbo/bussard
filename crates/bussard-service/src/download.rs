//! Running a download ([`bussard_download::flash`]) over a [`BusService`], and
//! the parameter-only download `bussard apply` and the MCP programming tier
//! write the differing parameter octets with (issue #274).
//!
//! [`flash_session`] is the one session driver: `bussard flash`, `flash
//! --parameters-only`, `apply` and `knx_apply_device` all open the download
//! through it. [`write_parameters`] is the parameter half of an apply: the
//! parameter-only plan, then a read-back of every octet it meant to change.

use bussard_download::{DeviceFacts, FlashOptions, FlashOutcome, FlashPlan, Progress, Session};
use bussard_mgmt::load::WriteError;
use bussard_mgmt::{Layer4Connection, LeaseChannel, MgmtError, Timeouts};
use bussard_model::IndividualAddress;
use bussard_secure::{Key16, SequenceHighWater};

use crate::bus::{Authorize, BusService, L4Options, Management, SourcePolicy};
use crate::error::ServiceError;
use crate::params::ParamDetail;

/// Environment variable that overrides the flash's per-attempt L4 ACK/response
/// timeout (in milliseconds). Unset in normal use, so the standard 3 s budget
/// applies. It exists so a stress run against a device that drops the L4
/// connection extremely frequently (the local sim's tiny `KNX_SIM_L4_BUDGET`,
/// or a pathologically flaky tunnel) detects each drop in milliseconds instead
/// of the full 3 s ACK-retransmit wait; resume-on-drop then reconnects
/// promptly. It does not change what the flash does, only how long it waits
/// before treating a silent peer as a dropped connection.
pub const FLASH_L4_TIMEOUT_MS_ENV: &str = "BUSSARD_FLASH_L4_TIMEOUT_MS";

/// The L4 timeout budget for a flash connection, honouring
/// [`FLASH_L4_TIMEOUT_MS_ENV`].
pub fn flash_l4_timeouts() -> Option<Timeouts> {
    bussard_model::dotenv::var(FLASH_L4_TIMEOUT_MS_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|ms| Timeouts {
            ack_timeout: std::time::Duration::from_millis(ms),
            max_repetitions: 1,
            response_timeout: std::time::Duration::from_millis(ms),
            absent_on_negative_confirmation: false,
        })
}

/// Opens the L4 connection to the flash target through the service.
///
/// The download ([`bussard_download::Session`]) runs over this single
/// connection for its whole duration, like ETS: the lease builds a
/// [`LeaseChannel`], so the flash observes the bus without stealing frames
/// from other subscribers.
pub struct ServiceConnector<'a> {
    /// The service the connections are leased from.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The checked source address.
    pub source: IndividualAddress,
    /// The KNX Data Secure tool key for the target, when the device is
    /// security-activated (issue #71, spec §6.2). `None` is the plain,
    /// byte-identical path; `Some` wraps every management APDU behind
    /// A_SecureData. The send sequence continues from `secure_seq`, so a
    /// reconnect after a master reset never replays a sequence the device has
    /// already accepted.
    pub secure_tool_key: Option<Key16>,
    /// The send-sequence high-water mark shared with every other session
    /// against this device (spec §5.9).
    pub secure_seq: SequenceHighWater,
}

impl bussard_download::Connector for ServiceConnector<'_> {
    type Channel = LeaseChannel;

    async fn connect(&mut self) -> Result<Layer4Connection<LeaseChannel>, WriteError> {
        // The service waits for a tunnel re-established after a gateway link
        // loss (issue #177) before the fresh T_Connect. The download session
        // authorizes itself, so the service does not.
        let options = L4Options {
            source: SourcePolicy::Known(self.source),
            tool_key: self.secure_tool_key.clone(),
            high_water: self.secure_seq.clone(),
            timeouts: flash_l4_timeouts().unwrap_or_default(),
            authorize: Authorize::Skip,
        };
        match self.service.connect_l4(self.target, &options).await {
            Ok(l4) => Ok(l4),
            Err(ServiceError::Mgmt(err)) => Err(WriteError::Mgmt(err)),
            // Leasing fails only if the bus actor is gone or the connection
            // went stale; either way the L4 session is unusable.
            Err(_) => Err(WriteError::Mgmt(MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            ))),
        }
    }

    fn link_losses(&self) -> u64 {
        // Lets the session tell a failure the gateway caused (the count moved)
        // from one the device caused, and retry the former (issue #192).
        self.service.handle().link_losses()
    }
}

/// Watches a download: each progress event, and the end.
pub trait FlashObserver {
    /// One progress event.
    fn progress(&mut self, event: Progress);
    /// The download ended; `verified` when it verified.
    fn finished(&mut self, verified: bool) {
        let _ = verified;
    }
}

/// An observer that ignores everything (the MCP tier reports the outcome).
impl FlashObserver for () {
    fn progress(&mut self, _event: Progress) {}
}

/// What [`flash_session`] needs besides the plan.
pub struct FlashRun<'a> {
    /// The service the connections are leased from.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The checked source address.
    pub source: IndividualAddress,
    /// The download options.
    pub options: FlashOptions,
    /// What the read-only pre-flight learned (object table, max APDU).
    pub facts: DeviceFacts,
    /// The KNX Data Secure tool key, `None` on the plain path.
    pub tool_key: Option<Key16>,
    /// The send-sequence high-water mark shared across the command.
    pub high_water: SequenceHighWater,
    /// The pre-flight's still-open connection to take over (issue #213), or
    /// `None` to open a fresh one seeded with `facts`.
    pub handover: Option<Management>,
}

/// Runs `plan` on the device, then `after` on the session's last connection
/// (the one the post-restart verification ran on) when the flash verified,
/// before the disconnect. `after` gets `None` back when the flash failed or
/// did not verify.
///
/// The session is disconnected on every path, a mid-flash failure included,
/// so a failed download never leaves the L4 session open.
pub async fn flash_session<R>(
    run: FlashRun<'_>,
    plan: &FlashPlan,
    observer: &mut impl FlashObserver,
    after: impl AsyncFnOnce(&mut Layer4Connection<LeaseChannel>) -> R,
) -> (Result<FlashOutcome, WriteError>, Option<R>) {
    let connector = ServiceConnector {
        service: run.service,
        target: run.target,
        source: run.source,
        secure_tool_key: run.tool_key,
        secure_seq: run.high_water,
    };
    let bcu_key = run.options.bcu_key;
    let opened = match run.handover {
        Some(mut l4) => {
            // The write phase's timeout budget, as its own connections get.
            l4.set_timeouts(flash_l4_timeouts().unwrap_or_default());
            Session::adopt_with_facts(connector, l4, bcu_key, run.facts).await
        }
        None => Session::open_with_facts(connector, bcu_key, run.facts).await,
    };
    let mut session = match opened {
        Ok(session) => session,
        Err(err) => return (Err(err), None),
    };
    let result = bussard_download::flash(&mut session, plan, run.options, |p| {
        observer.progress(p);
    })
    .await;
    let verified = result.as_ref().is_ok_and(|outcome| outcome.ok());
    observer.finished(verified);
    let extra = if verified {
        Some(after(session.l4()).await)
    } else {
        None
    };
    let _ = session.into_disconnect().await;
    (result, extra)
}

/// How a parameter write ended.
#[derive(Debug)]
pub enum ParamWriteOutcome {
    /// The download verified and the read-back matches: `octets` changed
    /// octets were read back.
    Verified {
        /// How many changed octets the read-back checked.
        octets: usize,
    },
    /// The download ran but did not verify.
    NotVerified(Box<FlashOutcome>),
    /// The download failed.
    Failed(WriteError),
    /// The read-back does not match what was written.
    Mismatch(String),
}

impl ParamWriteOutcome {
    /// Whether the parameters were written and verified.
    pub fn ok(&self) -> bool {
        matches!(self, ParamWriteOutcome::Verified { .. })
    }

    /// The one line saying what went wrong, `None` when verified.
    pub fn failure(&self) -> Option<String> {
        match self {
            ParamWriteOutcome::Verified { .. } => None,
            ParamWriteOutcome::NotVerified(outcome) => Some(format!(
                "the parameter download did not verify: {outcome:?}"
            )),
            ParamWriteOutcome::Failed(err) => Some(format!("the parameter download failed: {err}")),
            ParamWriteOutcome::Mismatch(reason) => {
                Some(format!("the parameter read-back does not match: {reason}"))
            }
        }
    }
}

/// Writes the parameter octets that differ (the `flash --parameters-only`
/// download `partial`, built by [`crate::params::build_device_plan`]) and
/// verifies them by reading the memory back on `read_options`.
///
/// The one parameter write of `bussard apply` and `knx_apply_device`.
///
/// # Errors
///
/// The read-back session could not be opened.
#[allow(clippy::too_many_arguments)] // one write phase's context
pub async fn write_parameters(
    service: &BusService,
    target: IndividualAddress,
    source: IndividualAddress,
    partial: &FlashPlan,
    detail: &ParamDetail,
    tool_key: Option<Key16>,
    high_water: SequenceHighWater,
    read_options: &L4Options,
    observer: &mut impl FlashObserver,
) -> Result<ParamWriteOutcome, ServiceError> {
    let facts = DeviceFacts {
        object_table: detail.resident.object_table.clone(),
        ..DeviceFacts::default()
    };
    let options = FlashOptions {
        bcu_key: None,
        verify_after_restart: true,
        skip_matching_mcb: false,
    };
    let run = FlashRun {
        service,
        target,
        source,
        options,
        facts,
        tool_key,
        high_water,
        handover: None,
    };
    let (outcome, _) = flash_session(run, partial, observer, async |_| {}).await;
    match outcome {
        Ok(outcome) if outcome.ok() => {}
        Ok(outcome) => return Ok(ParamWriteOutcome::NotVerified(Box::new(outcome))),
        Err(err) => return Ok(ParamWriteOutcome::Failed(err)),
    }
    let after = service
        .with_l4(target, read_options, async |l4| {
            Ok::<_, ServiceError>(bussard_download::read_parameter_regions(l4, &detail.plan).await)
        })
        .await?;
    Ok(
        match bussard_download::verify_readback(
            partial,
            &after,
            &bussard_download::runtime_segments(&detail.plan),
        ) {
            Ok(octets) => ParamWriteOutcome::Verified { octets },
            Err(reason) => ParamWriteOutcome::Mismatch(reason),
        },
    )
}
