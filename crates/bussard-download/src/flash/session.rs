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

/// The numbered-exchange count at which the flash proactively cycles the L4
/// connection (a graceful `T_Disconnect`/`T_Connect` + re-authorize) *between*
/// steps, to stay under the device's per-connection budget.
///
/// A real connection-oriented device drops a long-held L4 connection after a
/// bounded number of numbered exchanges — the KNX Virtual DA.tp device was
/// observed to drop at ~35, and a whole post-master-reset flow on one connection
/// sits right at that edge, failing ~50% of the time. ETS reconnects the L4
/// connection periodically within a download (its capture shows repeated
/// T_Disconnect/T_Connect cycles at 2–65-exchange intervals) to stay well clear.
///
/// 10 is deliberately well under the observed drop point (16–35, historically as
/// low as ~7 on the live KV DA.tp) so a proactive cycle usually lands before the
/// device drops: the check runs *before* each step, and a single step (a chunked
/// memory write) can add several exchanges, so the effective peak before a cycle
/// is `THRESHOLD` + one step's exchanges. The threshold is intentionally
/// conservative rather than tuned to the mean because the drop is
/// non-deterministic; whatever it misses is caught by resume-on-drop (see
/// [`flash`](super::flash)), which reconnects and re-runs the step when the connection dies
/// unexpectedly mid-flow. Only sessions that
/// [`can_reconnect`](Session::can_reconnect) cycle; a single-connection session
/// ([`Session::from_connection`], mocks) keeps the one-connection path.
pub(super) const RECONNECT_EXCHANGE_THRESHOLD: u32 = 10;

/// Environment variable that overrides [`RECONNECT_EXCHANGE_THRESHOLD`] with a
/// numeric value. Set by the flash-mock periodic-reconnect test so it can drive
/// the cycle at a low, deterministic exchange count against a small procedure;
/// unset in normal use, so the default 20 applies. Behaviour is otherwise
/// unchanged (a value of 0 disables proactive cycling entirely).
pub(super) const RECONNECT_THRESHOLD_ENV: &str = "BUSSARD_FLASH_RECONNECT_EXCHANGES";

/// The proactive-reconnect exchange threshold, honouring [`RECONNECT_THRESHOLD_ENV`]
/// for tests. A value of 0 disables proactive cycling.
pub(super) fn reconnect_exchange_threshold() -> u32 {
    std::env::var(RECONNECT_THRESHOLD_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(RECONNECT_EXCHANGE_THRESHOLD)
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
        Session {
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
        Self::authorize(&mut l4, bcu_key, &mut authorize_outcomes).await?;
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
    async fn authorize(
        l4: &mut Layer4Connection<C::Channel>,
        bcu_key: Option<u32>,
        cache: &mut BTreeMap<u16, bussard_mgmt::AuthorizeOutcome>,
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
    pub(super) async fn reconnect(&mut self) -> Result<(), WriteError> {
        // Drop the dead connection outright (do NOT try to T_Disconnect — the
        // device is mid-reboot and will not answer).
        self.l4 = None;
        let connector =
            self.connector
                .as_mut()
                .ok_or(WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                    bussard_transport::TransportError::Closed,
                )))?;
        let mut l4 = connector.connect().await?;
        Self::authorize(&mut l4, self.bcu_key, &mut self.authorize_outcomes).await?;
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
    pub(super) async fn reconnect_after_reboot(&mut self) -> Result<(), WriteError> {
        // Drop the dead connection up front: on the real path it holds the bus
        // lease, and the probes below need it. Dropping (rather than
        // disconnecting) is right — the peer is mid-reboot and will not answer.
        self.l4 = None;
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
        self.reconnect().await
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
        let connector =
            self.connector
                .as_mut()
                .ok_or(WriteError::Mgmt(bussard_mgmt::MgmtError::Transport(
                    bussard_transport::TransportError::Closed,
                )))?;
        let mut l4 = connector.connect().await?;
        Self::authorize(&mut l4, self.bcu_key, &mut self.authorize_outcomes).await?;
        // Re-seed the device-stable max APDU onto the fresh connection without a
        // round-trip, so scaling persists across the cycle without spending an
        // exchange against the tight per-connection budget (issue #58).
        l4.set_max_apdu(self.max_apdu);
        self.l4 = Some(l4);
        Ok(())
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
