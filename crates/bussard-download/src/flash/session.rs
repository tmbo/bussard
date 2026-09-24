//! The flash [`Session`]: one Layer-4 connection to the device plus the
//! machinery to survive its loss.
//!
//! A [`Connector`] opens connections; the session counts exchanges, reconnects
//! proactively before a per-connection budget runs out, and re-runs idempotent
//! primitives (load control, segment allocation, state and memory reads) across
//! an unexpected connection death.

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    LoadControl, LoadState, WriteError, allocate_segment, is_connection_death, read_load_state,
    write_load_control,
};
use bussard_mgmt::tables::OT_APPLICATION_PROGRAM;
use bussard_mgmt::{MgmtError, load};
use std::collections::BTreeMap;

/// The **upper bound** on how long to wait for a device to come back after a
/// restart (a master-reset `A_Restart` or the terminal one) before giving up on
/// the reboot. A real ETS→KNX-Virtual capture showed ~6.5s of silence while the
/// device rebooted; real devices vary, so the bound is deliberately generous.
///
/// It is a *bound*, not a fixed sleep: after
/// [`REBOOT_PROBE_MIN_WAIT`] of silence the session polls the device with a cheap
/// liveness probe every [`REBOOT_PROBE_INTERVAL`] (see
/// [`Session::reconnect_after_reboot`]), so a device that is back after 6.5 s is
/// picked up then instead of costing the full bound. Only a device that never
/// answers pays it.
const MASTER_RESET_REBOOT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the post-restart poll stays quiet before its first probe.
///
/// A device that is still shutting down can answer for a few hundred
/// milliseconds after it acknowledged the restart; probing immediately would
/// mistake that dying stack for a rebooted one and resume the procedure against
/// a device that is about to go away. Waiting a short minimum first makes the
/// first probe meaningful. Capped by the overall bound (see
/// [`reboot_wait_bound`]) so a test that shrinks the bound stays fast.
const REBOOT_PROBE_MIN_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// How long to wait between post-restart liveness probes.
const REBOOT_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// The tight L4 budget one post-restart liveness probe runs on: a device that is
/// still rebooting must be ruled out in a fraction of a second, not in the
/// standard 3 s ACK wait times four attempts.
const REBOOT_PROBE_TIMEOUTS: bussard_mgmt::Timeouts = bussard_mgmt::Timeouts {
    ack_timeout: std::time::Duration::from_millis(400),
    max_repetitions: 0,
    response_timeout: std::time::Duration::from_millis(400),
};

/// Environment variable that overrides [`MASTER_RESET_REBOOT_WAIT`] with a
/// millisecond value. Set by the mock-device restart tests so the reboot wait
/// does not stall them; unset in normal use, so the full generous bound applies.
/// It caps the minimum quiet period too, so a tiny value really is a tiny wait.
const REBOOT_WAIT_MS_ENV: &str = "BUSSARD_FLASH_REBOOT_WAIT_MS";

/// The upper bound on the post-restart wait, honouring [`REBOOT_WAIT_MS_ENV`].
fn reboot_wait_bound() -> std::time::Duration {
    std::env::var(REBOOT_WAIT_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
        .unwrap_or(MASTER_RESET_REBOOT_WAIT)
}

/// The upper bound on the post-restart readiness poll for a **Data Secure**
/// device (issue #166).
///
/// ETS's erase-7 restart of 1.1.12 took about 14 s before the device answered
/// again (secure-1-1-12 capture), and a Secure device can answer at the
/// transport layer before its security layer is ready. The poll therefore
/// keeps probing for up to 30 s, comfortably above the 14 s the capture shows;
/// a device whose plain descriptor probe answers earlier ends the wait then.
/// Honours [`REBOOT_WAIT_MS_ENV`] like the plain bound, so tests stay fast.
const SECURE_REBOOT_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The first pause between two Secure readiness probes; it doubles after each
/// unanswered probe up to [`SECURE_PROBE_MAX_BACKOFF`] (1, 2, 4, 8, 8 … s).
const SECURE_PROBE_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// The cap on the pause between two Secure readiness probes.
const SECURE_PROBE_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(8);

/// The upper bound on the post-restart poll of a Data Secure device, honouring
/// [`REBOOT_WAIT_MS_ENV`].
fn secure_reboot_wait_bound() -> std::time::Duration {
    std::env::var(REBOOT_WAIT_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
        .unwrap_or(SECURE_REBOOT_WAIT)
}

/// The S-A_Sync retry policy for the first connection after a restart bussard
/// triggered: [`SyncRetry::after_restart`](bussard_mgmt::SyncRetry::after_restart),
/// with its backoff capped by the reboot bound so a test that shrinks the bound
/// does not sleep whole seconds.
fn sync_retry_after_restart() -> bussard_mgmt::SyncRetry {
    bussard_mgmt::SyncRetry::after_restart().with_backoff_cap(secure_reboot_wait_bound())
}

/// The numbered-exchange count at which a flash of a **KNX Virtual** device
/// proactively cycles the L4 connection (a graceful `T_Disconnect`/`T_Connect` +
/// re-authorize) *between* steps, to stay under the device's per-connection
/// budget.
///
/// The KNX Virtual DA.tp device drops a long-held L4 connection after a bounded
/// number of numbered exchanges: observed at ~35, at 16–35 in later runs and
/// historically as low as ~7 (issue #80). A whole post-master-reset flow on one
/// connection sits right at that edge, failing ~50% of the time without cycling.
///
/// Real devices do not drop a connection this way, and ETS holds one connection
/// for the whole download (every System 7 capture: `schaltaktor-8fach-1-1-49`,
/// `pm-mini-1-1-52`, `meteodata-1-1-202-new`). On a Data Secure device each cycle
/// also costs an S-A_Sync_Req/Res pair (issue #168). So the cycling is **off by
/// default** and switched on only for a plan that targets KNX Virtual
/// ([`FlashPlan::targets_knx_virtual`](super::FlashPlan::targets_knx_virtual)),
/// issue #116. [`RECONNECT_THRESHOLD_ENV`] overrides the choice either way.
///
/// 10 is deliberately well under the observed drop point so a proactive cycle
/// usually lands before the device drops: the check runs *before* each step,
/// and a single step (a chunked memory write) can add several exchanges, so the
/// effective peak before a cycle is `THRESHOLD` + one step's exchanges. The
/// check is between steps, never mid memory write, so a chunked write is never
/// split across a reconnect. Whatever it misses is caught by resume-on-drop (see
/// [`flash`](super::flash)), which reconnects and re-runs the step when the
/// connection dies unexpectedly mid-flow. Only sessions that
/// [`can_reconnect`](Session::can_reconnect) cycle; a single-connection session
/// ([`Session::from_connection`], mocks) keeps the one-connection path.
pub(super) const RECONNECT_EXCHANGE_THRESHOLD: u32 = 10;

/// Environment variable that overrides the proactive-reconnect threshold with a
/// numeric value, for every device: `0` disables cycling (also for KNX
/// Virtual), any other value cycles at that exchange count (also for a real
/// device). The flash-mock periodic-reconnect tests set it to drive the cycle at
/// a low, deterministic exchange count against a small procedure; a campaign
/// run can set it to bring the cycling back for a device that needs it.
pub(super) const RECONNECT_THRESHOLD_ENV: &str = "BUSSARD_FLASH_RECONNECT_EXCHANGES";

/// The proactive-reconnect exchange threshold for `plan`: the
/// [`RECONNECT_THRESHOLD_ENV`] value when set, else
/// [`RECONNECT_EXCHANGE_THRESHOLD`] for a KNX Virtual target and 0 (no
/// proactive cycling, one connection like ETS) for every other device.
pub(super) fn reconnect_exchange_threshold(plan: &super::FlashPlan) -> u32 {
    let env = std::env::var(RECONNECT_THRESHOLD_ENV).ok();
    threshold_for(env.as_deref(), plan.targets_knx_virtual())
}

/// [`reconnect_exchange_threshold`] with the environment value passed in, so
/// the choice is testable without touching the process environment.
fn threshold_for(env: Option<&str>, knx_virtual: bool) -> u32 {
    env.and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(if knx_virtual {
            RECONNECT_EXCHANGE_THRESHOLD
        } else {
            0
        })
}

/// How many times a single flash step is retried after an *unexpected* mid-flow
/// connection death before the flash gives up on it.
///
/// This is the resume-on-drop bound (see [`flash`](super::flash)). A connection-oriented device
/// (KNX Virtual DA.tp) drops the L4 connection at a non-deterministic exchange
/// count that no fixed proactive threshold can reliably stay under; when a step
/// fails with a connection-death error and the session can reconnect, the engine
/// cycles the L4 connection and re-runs the step. Load state and allocated
/// segments are persistent device state that survive the drop, so re-running the
/// step on the fresh connection is safe (memory writes are absolute/relative
/// addressed; a re-issued StartLoading/allocate on an already-open object is
/// idempotent enough).
///
/// The bound is *per step*, but **any forward progress resets it** (each step that
/// completes starts the next step with a full budget): a healthy flash that simply
/// needs a reconnect every few steps is unbounded, while a genuinely dead device
/// that never completes a single step fails cleanly after this many reconnect
/// attempts rather than looping forever.
pub(super) const MAX_RESUME_RECONNECTS: u32 = 5;

/// How long a reconnect (after a device restart, or after a mid-flow
/// connection death) keeps retrying across gateway link losses, measured from
/// the first failed attempt (issue #192).
///
/// The sum of the two budgets a retry can spend: the tunnel re-establish
/// budget ([`TUNNEL_RECONNECT_BUDGET`](bussard_transport::config::TUNNEL_RECONNECT_BUDGET),
/// 60 s, which the connector waits out before its `T_Connect`) and the Data
/// Secure readiness poll ([`SECURE_REBOOT_WAIT`], 30 s). A link that stays down
/// longer surfaces the transport's own error, which names the gateway.
const RECONNECT_RESUME_BUDGET: std::time::Duration = std::time::Duration::from_secs(
    bussard_transport::config::TUNNEL_RECONNECT_BUDGET.as_secs() + SECURE_REBOOT_WAIT.as_secs(),
);

/// Whether a failed reconnect attempt is worth repeating (issue #192): a
/// connection death (see [`is_connection_death`]), or any silence-like failure
/// while the gateway link was lost during the attempt (`link_lost`). A Data
/// Secure S-A_Sync that went unanswered because the tunnel was down, or an
/// authorize that timed out for the same reason, says nothing about the
/// device. A tunnel that could not be re-established at all
/// ([`TransportError::TunnelLost`](bussard_transport::TransportError::TunnelLost))
/// is final: its budget is already spent and its message names the gateway.
fn reconnect_retryable(err: &WriteError, link_lost: bool) -> bool {
    if is_connection_death(err) {
        return true;
    }
    link_lost
        && matches!(
            err,
            WriteError::Mgmt(MgmtError::Secure { .. })
                | WriteError::Mgmt(MgmtError::Transport(
                    bussard_transport::TransportError::Timeout(_)
                ))
        )
}

/// Opens the [`Layer4Connection`] to the flash target.
///
/// A [`Session`] uses this to establish the single L4 connection the whole
/// download runs over — like ETS, one stable connection for the entire flash. The
/// CLI's implementation leases the bus and builds a `LeaseChannel`; tests script
/// one directly. Kept as an async trait (rather than a bare closure) so the
/// returned connection's channel type `Ch` is named and the future is nameable
/// without boxing.
#[allow(async_fn_in_trait)]
pub trait Connector {
    /// The channel the produced connection drives.
    type Channel: L4Channel;

    /// Opens the connection to the flash target.
    async fn connect(&mut self) -> Result<Layer4Connection<Self::Channel>, WriteError>;

    /// How many times the gateway link under this connector has been lost so
    /// far (a monotonic count; the CLI reports the bus actor's
    /// [`link_losses`](bussard_bus::BusHandle::link_losses)).
    ///
    /// The session compares it before and after a reconnect attempt: a
    /// failure while the count moved was caused by the gateway, not the
    /// device, and is retried once the tunnel is back (issue #192). The
    /// default, `0`, means "never lost" and keeps the pre-#192 behaviour.
    fn link_losses(&self) -> u64 {
        0
    }
}

/// The [`Connector`] type of a [`Session`] built from an already-open connection
/// via [`Session::from_connection`].
///
/// It only names the channel type `Ch` so `Session<SingleConnector<Ch>>` is a
/// concrete type; it is never actually connected through (the session already
/// holds its connection), so [`connect`](Connector::connect) is unreachable.
pub struct SingleConnector<Ch: L4Channel>(std::marker::PhantomData<Ch>);

impl<Ch: L4Channel> Connector for SingleConnector<Ch> {
    type Channel = Ch;

    async fn connect(&mut self) -> Result<Layer4Connection<Ch>, WriteError> {
        // Unreachable: a session built from an already-open connection never
        // opens another. Present only to satisfy the `Connector` bound.
        Err(WriteError::Mgmt(MgmtError::Transport(
            bussard_transport::TransportError::Closed,
        )))
    }
}

impl<Ch: L4Channel> Session<SingleConnector<Ch>> {
    /// Wraps one already-open [`Layer4Connection`] as a session.
    ///
    /// The returned session flashes over exactly this connection. This is the
    /// drop-in for callers and tests that open the connection themselves.
    pub fn from_connection(l4: Layer4Connection<Ch>) -> Session<SingleConnector<Ch>> {
        let secure = l4.is_secure();
        Session {
            secure,
            target: l4.target(),
            l4: Some(l4),
            connector: None,
            bcu_key: None,
            authorize_outcomes: BTreeMap::new(),
            facts: DeviceFacts::default(),
            max_apdu: None,
        }
    }
}

/// What the read-only pre-flight already learned about the device, carried into
/// the write phase so the flash does not pay for discovering it a second time.
///
/// `bussard flash` runs a read-only probe before it shows the plan (issue #79):
/// it walks `PID_OBJECT_TYPE` over every interface object, presents
/// `A_Authorize_Request`, and reads each object's load state. All three are
/// device-stable facts, but the write phase used to rediscover them on its own
/// connection: another full object-table walk, another authorize (a device that
/// does not implement authorize burns a full `RESPONSE_TIMEOUT` answering
/// nothing), and another `PID_MAX_APDU_LENGTH` read.
///
/// Handing the pre-flight's findings to [`Session::open_with_facts`] removes
/// that duplication. Every field is optional/empty-tolerant: an empty
/// [`DeviceFacts`] (or [`Session::open_with_key`], which supplies none) restores
/// the rediscover-everything behaviour byte-for-byte, which is what the mock and
/// oracle tests pin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceFacts {
    /// The interface-object table (`index → PID_OBJECT_TYPE`) the pre-flight
    /// walked, in index order. Empty when it could not be read, in which case
    /// the flash walks it itself.
    pub object_table: Vec<(u8, u16)>,
    /// The authorize outcome the pre-flight observed on its own connection.
    ///
    /// Only an [`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)
    /// outcome changes what the write phase does — it stops re-presenting a key
    /// to a device that answers nothing, saving a full `RESPONSE_TIMEOUT` per
    /// connection window. A `Granted` is per-connection state that a fresh
    /// `T_Connect` clears, so it is recorded but still re-presented.
    pub authorize: Option<bussard_mgmt::AuthorizeOutcome>,
    /// The device's `PID_MAX_APDU_LENGTH`, when the pre-flight negotiated it.
    /// Device-stable, so the session seeds it instead of spending an exchange
    /// re-reading it.
    pub max_apdu: Option<u16>,
}

impl DeviceFacts {
    /// The application-program object index this table names, if any.
    ///
    /// `None` when the pre-flight read no table, or read one that carries no
    /// interface-object of type 3 — either way the flash falls back to its own
    /// discovery walk rather than guessing.
    pub fn application_object(&self) -> Option<u8> {
        self.object_table
            .iter()
            .find(|(_, ot)| *ot == OT_APPLICATION_PROGRAM)
            .map(|(index, _)| *index)
    }
}

/// An L4 session to the flash target: it owns the open [`Layer4Connection`] the
/// whole download runs over.
///
/// Like ETS, the download runs over a single stable connection for its entire
/// duration; the engine borrows `session.l4()` for each step. `apply`/`reconstruct`
/// keep borrowing a plain `Layer4Connection` and are untouched.
///
/// The session also retains the [`Connector`] it was opened from and the
/// authorization key, so it can re-establish the connection **once** after a
/// spec-required device restart (an `LdCtrlMasterReset`): the device reboots and
/// drops the L4 link, and the procedure must continue on a fresh, re-authorized
/// connection. This is the single reconnect-after-restart the KNX spec mandates
/// for a master reset — not general connection cycling.
///
/// The type parameter `C` names the [`Connector`] the session was opened from, so
/// the connection's channel type stays nameable without boxing.
pub struct Session<C: Connector> {
    /// The open connection the download runs over.
    l4: Option<Layer4Connection<C::Channel>>,
    /// The connector the session was opened from, retained so a master-reset
    /// step can re-open the connection after the device reboots. `None` for a
    /// session built from an already-open connection ([`Session::from_connection`]),
    /// which cannot reconnect on its own.
    connector: Option<C>,
    /// The authorization key to re-present on a reconnect (the free-access key
    /// when `None`), so the resumed connection is authorized exactly as the
    /// original was.
    bcu_key: Option<u32>,
    /// The first successful [`AuthorizeOutcome`] observed per target device
    /// (keyed by its raw individual address), cached for the life of the session.
    ///
    /// Only an [`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)
    /// outcome causes a later re-authorize to be *skipped*: such a device does
    /// not implement authorize and answers the request with silence — a full
    /// `RESPONSE_TIMEOUT` burned on every reconnect/cycle window (issue #58).
    /// Once we know a target is unsupported we stop paying that wait.
    ///
    /// A [`Granted`](bussard_mgmt::AuthorizeOutcome::Granted) outcome is cached
    /// for observability but does NOT skip re-authorize: authorization is
    /// per-connection state that a `T_Disconnect`/reboot clears, so a device with
    /// a real write gate must re-present the key on every fresh connection. A
    /// `Denied` never reaches the cache — it fails the open before insertion.
    authorize_outcomes: BTreeMap<u16, bussard_mgmt::AuthorizeOutcome>,
    /// What the CLI's read-only pre-flight already learned about this device
    /// ([`DeviceFacts`]), so the flash does not rediscover it. Empty for a
    /// session opened without facts (the library default and every mock test),
    /// which keeps the rediscover-everything wire sequence.
    facts: DeviceFacts,
    /// The device's `PID_MAX_APDU_LENGTH`, negotiated once on the first connection
    /// and re-seeded (not re-read) onto every later window's connection.
    ///
    /// The value is device-stable, so re-reading it each window would only burn a
    /// numbered exchange against the tight per-connection budget and shift where a
    /// mid-step drop lands (issue #58). Caching it at the session level keeps every
    /// window's exchange sequence identical to an un-negotiated flash after the
    /// first, while still scaling chunks to the device.
    max_apdu: Option<u16>,
    /// Whether the session's connections wrap management APDUs with a Data
    /// Secure tool key. A restart the flash triggers then ends with the Secure
    /// readiness probe and the longer S-A_Sync retry (issue #166); a plain
    /// session keeps its wire sequence unchanged.
    secure: bool,
    /// The flash target, for log lines written while no connection is open.
    target: bussard_model::IndividualAddress,
}

impl<C: Connector> Session<C> {
    /// Opens the connection and wraps it in a session, authorizing it with the
    /// free-access key.
    ///
    /// Equivalent to [`open_with_key`](Session::open_with_key) with `None` — the
    /// connection presents [`FREE_ACCESS_KEY`](bussard_mgmt::apci::FREE_ACCESS_KEY)
    /// right after connect (issue #52 finding #1). A device that does not implement
    /// authorize is tolerated; a non-zero granted level fails with
    /// `MgmtError::AccessDenied`.
    pub async fn open(connector: C) -> Result<Session<C>, WriteError> {
        Session::open_with_key(connector, None).await
    }

    /// Opens the connection and authorizes it with `bcu_key` (or the free-access
    /// key when `None`).
    ///
    /// Equivalent to [`open_with_facts`](Session::open_with_facts) with an empty
    /// [`DeviceFacts`]: the session discovers everything itself, which is the
    /// standalone-library behaviour the mock and oracle wire traces pin.
    pub async fn open_with_key(
        connector: C,
        bcu_key: Option<u32>,
    ) -> Result<Session<C>, WriteError> {
        Session::open_with_facts(connector, bcu_key, DeviceFacts::default()).await
    }

    /// Opens the connection with what a read-only pre-flight already learned
    /// about the device ([`DeviceFacts`]).
    ///
    /// Two of the three facts change what this open costs on the wire:
    ///
    /// * an [`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)
    ///   authorize outcome seeds the per-target cache, so no key is presented to
    ///   a device that answers nothing — saving one `RESPONSE_TIMEOUT` here and
    ///   one on every later reconnect/cycle;
    /// * a known `PID_MAX_APDU_LENGTH` is seeded instead of re-read, saving a
    ///   numbered exchange against the tight per-connection budget.
    ///
    /// The object table is not used here; it is consumed by [`flash`](super::flash) in place of
    /// its own discovery walk.
    pub async fn open_with_facts(
        mut connector: C,
        bcu_key: Option<u32>,
        facts: DeviceFacts,
    ) -> Result<Session<C>, WriteError> {
        let mut l4 = connector.connect().await?;
        let mut authorize_outcomes = BTreeMap::new();
        // Seed the pre-flight's verdict BEFORE authorizing: an "this device does
        // not implement authorize" finding is what makes `authorize` skip the
        // request entirely. A `Granted`/`Denied` verdict is per-connection state
        // and is deliberately not seeded — this fresh connection must earn it.
        if let Some(outcome @ bussard_mgmt::AuthorizeOutcome::Unsupported { .. }) = &facts.authorize
        {
            authorize_outcomes.insert(l4.target().raw(), outcome.clone());
        }
        let losses = connector.link_losses();
        Self::authorize(&mut l4, bcu_key, &mut authorize_outcomes, || {
            connector.link_losses() != losses
        })
        .await?;
        // Read PID_MAX_APDU_LENGTH once so memory/property chunks scale to the
        // device (issue #58). Best-effort: a failure leaves the conservative
        // standard-frame caps and never aborts the open. Cached at the session
        // level and re-seeded (not re-read) on later windows so it costs exactly
        // one exchange for the whole flash — or none, when the pre-flight already
        // negotiated it.
        let max_apdu = match facts.max_apdu {
            Some(known) => {
                l4.set_max_apdu(Some(known));
                Some(known)
            }
            None => l4.negotiate_max_apdu().await.ok().flatten(),
        };
        Ok(Session {
            secure: l4.is_secure(),
            target: l4.target(),
            l4: Some(l4),
            connector: Some(connector),
            bcu_key,
            authorize_outcomes,
            facts,
            max_apdu,
        })
    }

    /// Presents the free-access-or-`bcu_key` authorization on the connection,
    /// applying the tolerate-absence / fail-on-denied policy, consulting and
    /// populating the per-target [`authorize_outcomes`](Session::authorize_outcomes)
    /// cache.
    ///
    /// If a previous window on this target already found the device does not
    /// implement authorize ([`Unsupported`](bussard_mgmt::AuthorizeOutcome::Unsupported)),
    /// the request is skipped entirely — it would only burn another
    /// `RESPONSE_TIMEOUT` waiting for an answer the device never sends (issue
    /// #58). Otherwise the real authorize is presented (a `Granted` gate is
    /// per-connection and must be re-opened on every fresh connection), and the
    /// outcome recorded for the next window's decision.
    ///
    /// `link_lost` reports whether the gateway link was lost while the request
    /// ran. An unanswered authorize then says nothing about the device, so it is
    /// neither cached as "does not implement authorize" (which would skip the
    /// key on every later connection and leave the write gate closed) nor
    /// accepted: it fails as [`MgmtError::NoResponse`], a connection death the
    /// caller reconnects from (issue #192).
    async fn authorize(
        l4: &mut Layer4Connection<C::Channel>,
        bcu_key: Option<u32>,
        cache: &mut BTreeMap<u16, bussard_mgmt::AuthorizeOutcome>,
        link_lost: impl FnOnce() -> bool,
    ) -> Result<(), WriteError> {
        let target = l4.target().raw();
        if let Some(bussard_mgmt::AuthorizeOutcome::Unsupported { .. }) = cache.get(&target) {
            // This device does not implement authorize (seen in an earlier
            // window): re-presenting the key only stalls a full RESPONSE_TIMEOUT
            // on a device that will not answer. Skip it (issue #58).
            tracing::debug!(
                target = %l4.target(),
                "device previously found not to implement authorize; skipping re-authorize"
            );
            return Ok(());
        }
        let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
        let outcome = l4.authorize_or_fail(key).await.map_err(WriteError::Mgmt)?;
        if matches!(outcome, bussard_mgmt::AuthorizeOutcome::Unsupported { .. }) && link_lost() {
            tracing::debug!(
                target = %l4.target(),
                "authorize unanswered while the gateway link was lost; not caching it"
            );
            return Err(WriteError::Mgmt(MgmtError::NoResponse {
                address: l4.target(),
            }));
        }
        cache.insert(target, outcome);
        Ok(())
    }

    /// The open connection, for a step to drive.
    pub fn l4(&mut self) -> &mut Layer4Connection<C::Channel> {
        self.l4
            .as_mut()
            .expect("session always holds its open connection")
    }

    /// Whether this session can re-open its connection after a device restart.
    ///
    /// True when the session was opened from a [`Connector`] it can call again
    /// ([`Session::open`]/[`open_with_key`](Session::open_with_key)); false when it
    /// wraps a single already-open connection ([`Session::from_connection`]), which
    /// has no way to reconnect. The terminal-restart verify uses this to decide
    /// whether to re-read the load state *after* the reboot (a real device) or
    /// *before* it (a mock with no reconnect).
    pub fn can_reconnect(&self) -> bool {
        self.connector.is_some()
    }

    /// The pre-flight's interface-object table and the application-object index
    /// it names, when both are known.
    ///
    /// `None` when the session was opened without [`DeviceFacts`], or with facts
    /// whose table is empty or carries no application-program object — in which
    /// case the caller walks the table itself.
    pub(super) fn known_object_table(&self) -> Option<(u8, Vec<(u8, u16)>)> {
        let app_obj = self.facts.application_object()?;
        Some((app_obj, self.facts.object_table.clone()))
    }

    /// Re-establishes the L4 connection after a device restart, re-authorizing it.
    ///
    /// Used by the master-reset step and the terminal-restart verify: the device
    /// rebooted and dropped the
    /// connection, so the old `Layer4Connection` is dead. This drops it, opens a
    /// fresh connection via the retained [`Connector`], and re-presents the same
    /// authorization the original connection used, so the remaining procedure
    /// steps continue transparently. A session built from an already-open
    /// connection ([`Session::from_connection`]) has no connector to reconnect
    /// with and fails with [`MgmtError::Transport`]`(Closed)`.
    ///
    /// The reconnect itself survives a gateway link loss (issue #192): an
    /// attempt that dies (a connection death, or a silence while the link was
    /// lost) is repeated once the tunnel is back, up to
    /// [`MAX_RESUME_RECONNECTS`] times within [`RECONNECT_RESUME_BUDGET`].
    pub(super) async fn reconnect(&mut self) -> Result<(), WriteError> {
        let mut retries = 0u32;
        let mut first_failure: Option<tokio::time::Instant> = None;
        loop {
            let losses = self.link_losses();
            let err = match self.reconnect_once().await {
                Ok(()) => return Ok(()),
                Err(err) => err,
            };
            let link_lost = self.link_losses() != losses;
            let since = *first_failure.get_or_insert_with(tokio::time::Instant::now);
            if !self.may_retry_reconnect(&err, link_lost, retries, since) {
                return Err(err);
            }
            retries += 1;
            tracing::warn!(
                "reconnecting to {} failed ({err}); retrying (attempt {} of {})",
                self.target,
                retries + 1,
                MAX_RESUME_RECONNECTS + 1
            );
        }
    }

    /// One reconnect attempt: drops the dead connection, opens a fresh one via
    /// the retained [`Connector`] and adopts it.
    async fn reconnect_once(&mut self) -> Result<(), WriteError> {
        // Drop the dead connection outright (do NOT try to T_Disconnect — the
        // device is mid-reboot and will not answer).
        self.l4 = None;
        let connector =
            self.connector
                .as_mut()
                .ok_or(WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                    bussard_transport::TransportError::Closed,
                )))?;
        let losses = connector.link_losses();
        let l4 = connector.connect().await?;
        self.adopt(l4, losses).await
    }

    /// How many times the gateway link has been lost, as the connector reports
    /// it (`0` for a session without a connector).
    pub(super) fn link_losses(&self) -> u64 {
        self.connector.as_ref().map_or(0, Connector::link_losses)
    }

    /// Whether a failed reconnect attempt is repeated: the session can
    /// reconnect, the failure is [`reconnect_retryable`], and neither the retry
    /// count nor the [`RECONNECT_RESUME_BUDGET`] (counted from `since`, the
    /// first failure) is spent.
    fn may_retry_reconnect(
        &self,
        err: &WriteError,
        link_lost: bool,
        retries: u32,
        since: tokio::time::Instant,
    ) -> bool {
        self.can_reconnect()
            && reconnect_retryable(err, link_lost)
            && retries < MAX_RESUME_RECONNECTS
            && since.elapsed() < RECONNECT_RESUME_BUDGET
    }

    /// Authorizes `l4`, re-seeds the cached max APDU onto it and makes it the
    /// session connection. `losses` is the connector's link-loss count from
    /// before `l4` was opened, so an authorize the gateway swallowed is not
    /// mistaken for a device without authorize.
    async fn adopt(
        &mut self,
        mut l4: Layer4Connection<C::Channel>,
        losses: u64,
    ) -> Result<(), WriteError> {
        let connector = &self.connector;
        Self::authorize(&mut l4, self.bcu_key, &mut self.authorize_outcomes, || {
            connector.as_ref().map_or(0, Connector::link_losses) != losses
        })
        .await?;
        // Re-seed the device-stable max APDU onto the fresh connection without a
        // round-trip, so scaling persists across the cycle without spending an
        // exchange against the tight per-connection budget (issue #58).
        l4.set_max_apdu(self.max_apdu);
        self.l4 = Some(l4);
        Ok(())
    }

    /// Waits out a device reboot with a **bounded poll**, then re-establishes the
    /// authorized connection.
    ///
    /// Used after a master-reset `A_Restart` and after the terminal restart. The
    /// device is unreachable while it reboots, but how long that takes varies by
    /// device (~6.5 s on KNX Virtual, less on others), so this does not burn a
    /// fixed [`MASTER_RESET_REBOOT_WAIT`]:
    ///
    /// 1. stay quiet for [`REBOOT_PROBE_MIN_WAIT`] (capped by the overall bound)
    ///    so a device that is still *shutting down* is not mistaken for one that
    ///    has come back;
    /// 2. then, every [`REBOOT_PROBE_INTERVAL`], run a cheap liveness probe — a
    ///    throwaway `T_Connect` + `A_DeviceDescriptor_Read` + `T_Disconnect` on a
    ///    tight [`REBOOT_PROBE_TIMEOUTS`] budget — until it answers or the bound
    ///    from [`reboot_wait_bound`] elapses;
    /// 3. either way, finish with the ordinary [`reconnect`](Session::reconnect),
    ///    so the session connection is established exactly as before and a device
    ///    that never came back surfaces that reconnect's error unchanged.
    ///
    /// The probe deliberately runs on its **own** connection rather than on the
    /// session's: it must not touch the session's authorize cache (a still-booting
    /// device answers nothing, which an authorize would record as "does not
    /// implement authorize" and never retry) and it must not shift the session
    /// connection's numbered-exchange sequence.
    ///
    /// # Resuming across a gateway link loss (issue #192)
    ///
    /// A pulled LAN cable on the IP interface during this phase used to fail
    /// the flash with `connection to <ia> was disconnected`, leaving a
    /// factory-reset device behind. Now a failed attempt that is a connection
    /// death, or any silence while the gateway link was lost, starts the phase
    /// again once the tunnel is back: the readiness probe runs anew (the
    /// device may still be booting), then the session connection is opened and
    /// authorized (Data Secure S-A_Sync included). Bounded by
    /// [`MAX_RESUME_RECONNECTS`] attempts within [`RECONNECT_RESUME_BUDGET`]
    /// from the first failure; past that the last error surfaces unchanged.
    pub(super) async fn reconnect_after_reboot(&mut self) -> Result<(), WriteError> {
        let mut retries = 0u32;
        let mut first_failure: Option<tokio::time::Instant> = None;
        loop {
            // Drop the dead connection up front: on the real path it holds the
            // bus lease, and the probes need it. Dropping (rather than
            // disconnecting) is right — the peer is mid-reboot and will not
            // answer.
            self.l4 = None;
            let losses = self.link_losses();
            let result = if self.secure {
                self.reconnect_after_secure_reboot().await
            } else {
                self.reconnect_after_plain_reboot().await
            };
            let err = match result {
                Ok(()) => return Ok(()),
                Err(err) => err,
            };
            let link_lost = self.link_losses() != losses;
            let since = *first_failure.get_or_insert_with(tokio::time::Instant::now);
            if !self.may_retry_reconnect(&err, link_lost, retries, since) {
                return Err(err);
            }
            retries += 1;
            tracing::warn!(
                "the connection was lost while reconnecting to {} after its restart ({err}); \
                 waiting for the device again (attempt {} of {})",
                self.target,
                retries + 1,
                MAX_RESUME_RECONNECTS + 1
            );
        }
    }

    /// One plain post-restart wait: the bounded liveness poll of
    /// [`reconnect_after_reboot`](Session::reconnect_after_reboot), then one
    /// reconnect attempt.
    async fn reconnect_after_plain_reboot(&mut self) -> Result<(), WriteError> {
        let bound = reboot_wait_bound();
        let started = tokio::time::Instant::now();
        tokio::time::sleep(REBOOT_PROBE_MIN_WAIT.min(bound)).await;
        // Only a session that owns a connector can probe; one built from a single
        // open connection falls straight through to `reconnect`'s error.
        if self.connector.is_some() {
            let deadline = started + bound;
            loop {
                if self.probe_rebooted_device().await {
                    break;
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    tracing::debug!(
                        "device did not answer a liveness probe within the reboot bound; \
                         reconnecting anyway"
                    );
                    break;
                }
                tokio::time::sleep(REBOOT_PROBE_INTERVAL.min(deadline - now)).await;
            }
        }
        self.reconnect_once().await
    }

    /// One post-reboot liveness probe: is the device answering management again?
    ///
    /// Opens a throwaway connection through the retained [`Connector`], asks for
    /// the device descriptor on the tight [`REBOOT_PROBE_TIMEOUTS`] budget, and
    /// tears it down again. Every failure path — no connector, a connector error,
    /// a silent device — is just `false`, so a failed probe leaves no state
    /// behind: the throwaway connection (and, on the real path, its bus lease) is
    /// released before returning, and the session still holds no connection of its
    /// own.
    async fn probe_rebooted_device(&mut self) -> bool {
        let Some(connector) = self.connector.as_mut() else {
            return false;
        };
        let mut l4 = match connector.connect().await {
            Ok(l4) => l4,
            Err(_) => return false,
        };
        l4.set_timeouts(REBOOT_PROBE_TIMEOUTS);
        let alive = bussard_mgmt::read_device_descriptor(&mut l4).await.is_ok();
        // Close the probe connection either way: a clean `T_Disconnect` when it
        // answered (so the device frees the slot immediately), a no-op when the
        // probe already tore it down.
        let _ = l4.disconnect().await;
        alive
    }

    /// The Data Secure variant of [`reconnect_after_reboot`](Session::reconnect_after_reboot)
    /// (issue #166).
    ///
    /// A Secure device can T_ACK frames before its security layer is ready, so
    /// the first S-A_Sync_Req after a reboot may go unanswered. This follows
    /// ETS, which opens every secured session with a plain
    /// `A_DeviceDescriptor_Read`:
    ///
    /// 1. stay quiet for [`REBOOT_PROBE_MIN_WAIT`] (capped by the bound);
    /// 2. probe with `T_Connect` + a plain `A_DeviceDescriptor_Read` on the
    ///    tight [`REBOOT_PROBE_TIMEOUTS`] budget, backing off 1, 2, 4, 8, 8 … s
    ///    between probes until one answers or [`secure_reboot_wait_bound`]
    ///    (30 s) has passed since the reboot wait began;
    /// 3. keep the connection whose probe answered (no `T_Disconnect` /
    ///    `T_Connect` in between, as in the ETS capture), restore its normal
    ///    timeouts and authorize it. The authorize runs the S-A_Sync handshake
    ///    under [`SyncRetry::after_restart`](bussard_mgmt::SyncRetry::after_restart),
    ///    so a Sync_Req the device acknowledges but does not answer is repeated
    ///    on that connection.
    ///
    /// When no probe answers within the bound, a fresh connection is opened
    /// anyway with the same Sync retry, so a device that never came back
    /// surfaces its error unchanged.
    async fn reconnect_after_secure_reboot(&mut self) -> Result<(), WriteError> {
        let bound = secure_reboot_wait_bound();
        let started = tokio::time::Instant::now();
        let deadline = started + bound;
        tokio::time::sleep(REBOOT_PROBE_MIN_WAIT.min(bound)).await;
        let mut backoff = SECURE_PROBE_INITIAL_BACKOFF;
        let mut ready = None;
        if self.connector.is_some() {
            loop {
                if let Some(l4) = self.probe_secure_device().await {
                    ready = Some(l4);
                    break;
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    tracing::debug!(
                        "Secure device did not answer the plain descriptor probe within \
                         the reboot bound; reconnecting anyway"
                    );
                    break;
                }
                tokio::time::sleep(backoff.min(deadline - now)).await;
                backoff = backoff.saturating_mul(2).min(SECURE_PROBE_MAX_BACKOFF);
            }
        }
        let (mut l4, losses) = match ready {
            Some(ready) => ready,
            None => {
                let connector = self.connector.as_mut().ok_or(WriteError::Mgmt(
                    bussard_mgmt::MgmtError::Transport(bussard_transport::TransportError::Closed),
                ))?;
                let losses = connector.link_losses();
                (connector.connect().await?, losses)
            }
        };
        l4.set_sync_retry(sync_retry_after_restart());
        self.adopt(l4, losses).await
    }

    /// One Secure readiness probe: opens a connection, reads the device
    /// descriptor in the clear on the tight [`REBOOT_PROBE_TIMEOUTS`] budget and
    /// returns the connection, with its normal timeouts restored, when the device
    /// answered, with the connector's link-loss count from before it was
    /// opened. A silent device yields `None` and its connection is released.
    async fn probe_secure_device(&mut self) -> Option<(Layer4Connection<C::Channel>, u64)> {
        let connector = self.connector.as_mut()?;
        let losses = connector.link_losses();
        let mut l4 = connector.connect().await.ok()?;
        let normal = l4.timeouts();
        l4.set_timeouts(REBOOT_PROBE_TIMEOUTS);
        match bussard_mgmt::read_device_descriptor_unsecured(&mut l4).await {
            Ok(_) => {
                l4.set_timeouts(normal);
                Some((l4, losses))
            }
            Err(err) => {
                tracing::debug!(%err, "Secure readiness probe unanswered");
                let _ = l4.disconnect().await;
                None
            }
        }
    }

    /// Waits out a confirmed master reset (factory reset or confirmed restart)
    /// and re-establishes the authorized connection.
    ///
    /// The device answered the `A_Restart_Response` and is rebooting, so the old
    /// connection is dropped without a `T_Disconnect` (the ETS capture sends none
    /// after the factory reset either), then the session sleeps for `process_wait`
    /// (the device's own process time, already capped by
    /// [`bussard_mgmt::restart_process_wait`]) and finishes with the bounded
    /// liveness poll and reconnect of
    /// [`reconnect_after_reboot`](Session::reconnect_after_reboot).
    ///
    /// A session built from an already-open connection cannot reconnect and fails
    /// with [`MgmtError::Transport`]`(Closed)` before sleeping.
    pub(super) async fn reconnect_after_master_reset(
        &mut self,
        process_wait: std::time::Duration,
    ) -> Result<(), WriteError> {
        if !self.can_reconnect() {
            return Err(WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            )));
        }
        self.l4 = None;
        tokio::time::sleep(process_wait).await;
        self.reconnect_after_reboot().await
    }

    /// Proactively cycles the L4 connection **between** flash steps to stay under
    /// the device's per-connection numbered-exchange budget.
    ///
    /// Real connection-oriented devices (KNX Virtual, and the couplers ETS drives)
    /// drop a long-held L4 connection after a bounded number of numbered exchanges
    /// — the DA.tp device drops at ~35. ETS avoids that by reconnecting the L4
    /// connection periodically within a download; bussard does the same here.
    ///
    /// Unlike [`reconnect`](Session::reconnect) (used after a device *restart*,
    /// where the peer is mid-reboot and the old connection is already dead), this
    /// is a **graceful** cycle of a live connection: it sends a `T_Disconnect` to
    /// close the old connection cleanly, opens a fresh one via the retained
    /// [`Connector`], and re-presents the same authorization. The objects' load
    /// states — and their allocated segments — are *persistent device state*, not
    /// connection state, so they survive the `T_Disconnect`/`T_Connect` and the
    /// procedure resumes seamlessly on the fresh, zero-exchange connection.
    ///
    /// A session built from an already-open connection
    /// ([`Session::from_connection`]) has no connector and returns
    /// [`MgmtError::Transport`]`(Closed)` — but such a session never calls this
    /// (the flash loop only cycles when [`can_reconnect`](Session::can_reconnect)).
    pub(super) async fn cycle_l4(&mut self) -> Result<(), WriteError> {
        // Gracefully close the live connection with a T_Disconnect so the device
        // frees the old connection immediately (best-effort: a send error here is
        // irrelevant, the fresh T_Connect below re-establishes state regardless).
        if let Some(l4) = self.l4.take() {
            let _ = l4.disconnect().await;
        }
        // Open, authorize and re-seed the max APDU exactly as a reconnect does,
        // including its retry across a gateway link loss (issue #192): a cycle
        // that lands in a tunnel outage waits for the tunnel and tries again
        // instead of failing the flash between two steps.
        self.reconnect().await
    }

    /// The current L4 connection's numbered-exchange count, or 0 when the session
    /// holds no connection.
    pub(super) fn numbered_exchanges(&self) -> u32 {
        self.l4
            .as_ref()
            .map_or(0, Layer4Connection::numbered_exchanges)
    }

    /// Consumes the session and gracefully disconnects the open connection.
    pub async fn into_disconnect(self) -> bussard_mgmt::Result<()> {
        match self.l4 {
            Some(l4) => l4.disconnect().await,
            None => Ok(()),
        }
    }
}

/// Drives a `StartLoading` on the application object, enriching a non-conformant
/// load-state failure with discovery context.
///
/// A conformant device lands in `Loading`; [`write_load_control`] confirms that.
/// Load-state handling is strict: a device that does not report `Loading` (e.g.
/// reports `Loaded` instead) fails with [`WriteError::UnexpectedLoadState`], now
/// carrying the targeted object's discovered type and the full discovered object
/// table so the failure is actionable rather than a bare "object N did not reach
/// Loading". This strictness is intentional — it catches a device that cannot
/// hold this application before its memory is overrun.
pub(super) async fn start_loading<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    object_table: &[(u8, u16)],
) -> Result<(), WriteError> {
    match write_load_control(l4, app_obj, LoadControl::StartLoading).await {
        Ok(_) => Ok(()),
        Err(WriteError::UnexpectedLoadState {
            address,
            object_index,
            control,
            expected,
            actual,
            ..
        }) => {
            // Re-emit with the discovered object context folded in.
            let context = bussard_mgmt::LoadStateContext {
                object_type: object_table
                    .iter()
                    .find(|(idx, _)| *idx == object_index)
                    .map(|(_, ot)| *ot),
                object_table: object_table.to_vec(),
            };
            Err(WriteError::UnexpectedLoadState {
                address,
                object_index,
                control,
                expected,
                actual,
                context,
            })
        }
        Err(other) => Err(other),
    }
}

/// Allocates a relative segment, enriching a non-conformant load-state failure
/// with the discovered object context — like [`start_loading`].
///
/// [`allocate_segment`] raises [`WriteError::UnexpectedLoadState`] with an empty
/// context when the object is not `Loading` (its precondition, or the re-read
/// after the `AdditionalLoadControls` write) — a device that did not honour the
/// segment allocation (e.g. it reports `Loaded`, meaning it lacks memory for this
/// application). This folds the targeted object's discovered interface-object type
/// and the full discovered object table into any such failure so it is actionable.
///
/// `fill` mirrors the source `LdCtrlRelSegment`'s fill (`Mode`/`Fill`): `None` (the
/// DA.tp default) asks for a no-fill allocation, byte-identical to before;
/// `Some(b)` requests the device pre-fill the segment with `b`.
pub(super) async fn allocate_with_context<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    app_obj: u8,
    size: u32,
    fill: Option<u8>,
    object_table: &[(u8, u16)],
) -> Result<bussard_mgmt::SegmentAllocation, WriteError> {
    match allocate_segment(l4, app_obj, size, fill).await {
        Err(WriteError::UnexpectedLoadState {
            address,
            object_index,
            control,
            expected,
            actual,
            ..
        }) => {
            let context = bussard_mgmt::LoadStateContext {
                object_type: object_table
                    .iter()
                    .find(|(idx, _)| *idx == object_index)
                    .map(|(_, ot)| *ot),
                object_table: object_table.to_vec(),
            };
            Err(WriteError::UnexpectedLoadState {
                address,
                object_index,
                control,
                expected,
                actual,
                context,
            })
        }
        other => other,
    }
}

/// Retries a resumable flash primitive over the session across an *unexpected*
/// connection death, reconnecting and re-running it.
///
/// This is a `macro_rules!` (not a generic higher-order fn) because the retried
/// primitives borrow `session.l4()` for the duration of their future, a lifetime a
/// single closure type cannot express without boxing. It expands to a bounded
/// reconnect loop around the given expression, which it re-evaluates after each
/// reconnect — so the primitive must be idempotent (load state and allocated
/// segments are persistent device state, so re-issuing StartLoading / allocate /
/// LoadCompleted / a state read is safe). Bounded by [`MAX_RESUME_RECONNECTS`]
/// consecutive reconnects; each success is forward progress. A session that cannot
/// reconnect surfaces the death unchanged (the mock single-connection path).
///
/// Making each *primitive* resumable — rather than only whole steps — is what lets
/// a flash survive a per-connection exchange budget *smaller than a single step's
/// exchange count*: the step's constituent writes/reads each make forward progress
/// across windows, where a whole-step replay would straddle the same budget
/// boundary forever.
macro_rules! resume {
    ($session:expr, $op:expr) => {{
        let mut reconnects = 0u32;
        loop {
            match $op {
                Ok(value) => break Ok(value),
                Err(e) if resumable_death(&e, $session) && reconnects < MAX_RESUME_RECONNECTS => {
                    reconnects += 1;
                    $session.reconnect().await?;
                }
                Err(e) => break Err(e),
            }
        }
    }};
}

/// Session-aware, resume-on-drop [`write_load_control`].
pub(super) async fn write_load_control_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
    control: LoadControl,
) -> Result<LoadState, WriteError> {
    resume!(
        session,
        write_load_control(session.l4(), obj, control).await
    )
}

/// Session-aware, resume-on-drop [`start_loading`].
pub(super) async fn start_loading_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
    object_table: &[(u8, u16)],
) -> Result<(), WriteError> {
    resume!(
        session,
        start_loading(session.l4(), obj, object_table).await
    )
}

/// Session-aware, resume-on-drop [`allocate_with_context`].
pub(super) async fn allocate_with_context_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
    size: u32,
    fill: Option<u8>,
    object_table: &[(u8, u16)],
) -> Result<bussard_mgmt::SegmentAllocation, WriteError> {
    resume!(
        session,
        allocate_with_context(session.l4(), obj, size, fill, object_table).await
    )
}

/// Whether an error from a resumable flash operation is an *unexpected* connection
/// death this session can recover from by reconnecting: a connection-death (see
/// [`is_connection_death`]) on a session that [`can_reconnect`](Session::can_reconnect).
///
/// This is the shared predicate behind resume-on-drop: the initial discovery probe,
/// each plan step, and the final verify each retry on it (bounded by
/// [`MAX_RESUME_RECONNECTS`]). It is a free function rather than a generic
/// retry-a-closure helper because the retried operations borrow the session's
/// connection mutably for the duration of their future, which a single closure type
/// cannot express without boxing; each call site owns its own small retry loop
/// instead.
pub(super) fn resumable_death<C: Connector>(err: &WriteError, session: &Session<C>) -> bool {
    is_connection_death(err) && session.can_reconnect()
}

/// Reads one object's load state, **resuming at read granularity** over the
/// session across an unexpected connection death: on a connection-death it
/// reconnects and re-reads (the load state is persistent, so the read is
/// idempotent). Bounded by [`MAX_RESUME_RECONNECTS`] consecutive reconnects.
pub(super) async fn read_load_state_resumable<C: Connector>(
    session: &mut Session<C>,
    obj: u8,
) -> Result<LoadState, WriteError> {
    let mut reconnects = 0u32;
    loop {
        match read_load_state(session.l4(), obj).await {
            Ok(state) => return Ok(state),
            Err(e) if resumable_death(&e, session) && reconnects < MAX_RESUME_RECONNECTS => {
                reconnects += 1;
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Reads `len` octets at `addr`, resuming at read granularity over the session
/// across an unexpected connection death (like [`read_load_state_resumable`]).
pub(super) async fn read_memory_resumable<C: Connector>(
    session: &mut Session<C>,
    addr: u32,
    len: u8,
) -> Result<Vec<u8>, WriteError> {
    let mut reconnects = 0u32;
    loop {
        match load::read_memory(session.l4(), addr, len).await {
            Ok(got) => return Ok(got),
            Err(e) if resumable_death(&e, session) && reconnects < MAX_RESUME_RECONNECTS => {
                reconnects += 1;
                session.reconnect().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_for_cycles_only_knx_virtual_by_default() {
        // Issue #116: a real device holds one connection like ETS; only KNX
        // Virtual (issue #80) cycles proactively.
        assert_eq!(threshold_for(None, false), 0);
        assert_eq!(threshold_for(None, true), RECONNECT_EXCHANGE_THRESHOLD);
    }

    #[test]
    fn test_threshold_for_env_overrides_either_way() {
        assert_eq!(threshold_for(Some("0"), true), 0);
        assert_eq!(threshold_for(Some(" 7 "), false), 7);
        // An unparsable value falls back to the device-class default.
        assert_eq!(threshold_for(Some("often"), false), 0);
        assert_eq!(
            threshold_for(Some("often"), true),
            RECONNECT_EXCHANGE_THRESHOLD
        );
    }
}
