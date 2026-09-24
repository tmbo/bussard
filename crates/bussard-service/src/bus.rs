//! [`BusService`]: a bus connection opened under a [`WritePolicy`], plus the
//! management-session skeleton every device command shares.
//!
//! Before this type existed, each surface called `Bus::connect` itself and was
//! expected to remember `enforce_write_gate` first. The gate is now applied in
//! [`BusService::open`] (and [`BusService::from_handle`]), so there is no way to
//! obtain a transmitting service for a non-loopback gateway without the
//! operator's opt-in.

use std::time::Duration;

use bussard_bus::{Bus, BusHandle};
use bussard_mgmt::{Layer4Connection, LeaseChannel, MgmtError, Timeouts};
use bussard_model::IndividualAddress;
use bussard_secure::{Key16, SequenceHighWater};
use bussard_transport::ConnectionConfig;
use bussard_transport::write_gate::{WriteGate, gateway_display};

use crate::error::ServiceError;
use crate::policy::WritePolicy;

/// A management (layer-4, connection-oriented) session over a leased bus.
pub type Management = Layer4Connection<LeaseChannel>;

/// Where a management session's source individual address comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePolicy {
    /// Resolve the source from the tunnel and probe that no bus device answers
    /// there (see [`bussard_mgmt::checked_source`]). `skip: true` is the CLI's
    /// `--skip-address-check`.
    Check {
        /// Skip the probe and use the resolved source as is.
        skip: bool,
    },
    /// A source the caller already checked, e.g. once per sweep in `scan`.
    Known(IndividualAddress),
}

/// How a management session authorizes after `T_Connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorize {
    /// Do not send `A_Authorize_Request`.
    Skip,
    /// Present the key; a denial is logged at debug level and the session
    /// continues. Right for best-effort reads.
    BestEffort(u32),
    /// Present the key; a denial fails the session with
    /// [`MgmtError::AccessDenied`](bussard_mgmt::MgmtError::AccessDenied).
    Required(u32),
}

/// Options for [`BusService::connect_l4`] and [`BusService::with_l4`].
#[derive(Debug, Clone)]
pub struct L4Options {
    /// Where the source address comes from.
    pub source: SourcePolicy,
    /// The KNX Data Secure tool key, or `None` for plain management.
    pub tool_key: Option<Key16>,
    /// The send-sequence high-water mark shared by every secured session of one
    /// command, so a reconnect never reuses a sequence number.
    pub high_water: SequenceHighWater,
    /// The layer-4 timeout budget.
    pub timeouts: Timeouts,
    /// The authorize step.
    pub authorize: Authorize,
}

impl Default for L4Options {
    /// A checked source, plain management, default timeouts and a best-effort
    /// free-access authorize: what a read-only device command wants.
    fn default() -> Self {
        L4Options {
            source: SourcePolicy::Check { skip: false },
            tool_key: None,
            high_water: SequenceHighWater::new(),
            timeouts: Timeouts::default(),
            authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
        }
    }
}

/// A bus connection opened under a [`WritePolicy`].
///
/// Cloning is cheap: the clone shares the same bus actor. Closing any clone
/// closes the connection for all of them.
#[derive(Clone)]
pub struct BusService {
    config: ConnectionConfig,
    handle: BusHandle,
    policy: WritePolicy,
    gate: Option<WriteGate>,
    /// The send-sequence high-water mark of secured group telegrams (issue
    /// #172), shared by every clone so a long-lived server never repeats a
    /// sequence number.
    group_high_water: SequenceHighWater,
}

impl BusService {
    /// Applies the write gate for `policy` without connecting.
    ///
    /// A surface that asks for confirmation before it connects (the CLI) calls
    /// this first, so a refusal comes before the prompt. [`open`](Self::open)
    /// applies the same check again; it is cheap and has no side effects.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Gate`] for a transmitting policy against a non-loopback
    /// gateway without the opt-in.
    pub fn check(
        config: &ConnectionConfig,
        policy: WritePolicy,
    ) -> Result<Option<WriteGate>, ServiceError> {
        Ok(policy.check(config)?)
    }

    /// Applies the write gate for `policy`, then spawns the bus actor for
    /// `config`.
    ///
    /// Must be called from within a tokio runtime context: the actor is a
    /// spawned task, exactly as with [`Bus::connect`]. The actor connects in the
    /// background and reconnects on its own; use
    /// [`wait_connected`](Self::wait_connected) to wait for the first connect.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Gate`] when the gate refuses; nothing is connected then.
    pub fn open(config: ConnectionConfig, policy: WritePolicy) -> Result<BusService, ServiceError> {
        let gate = policy.check(&config)?;
        let (handle, _task) = Bus::connect(config.clone());
        Ok(BusService {
            config,
            handle,
            policy,
            gate,
            group_high_water: SequenceHighWater::new(),
        })
    }

    /// Wraps a bus actor the caller already spawned, applying the same gate as
    /// [`open`](Self::open).
    ///
    /// For tests that drive a mock gateway, and for a surface that must spawn
    /// the actor itself.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Gate`] when the gate refuses.
    pub fn from_handle(
        config: ConnectionConfig,
        handle: BusHandle,
        policy: WritePolicy,
    ) -> Result<BusService, ServiceError> {
        let gate = policy.check(&config)?;
        Ok(BusService {
            config,
            handle,
            policy,
            gate,
            group_high_water: SequenceHighWater::new(),
        })
    }

    /// Waits up to `timeout` for the bus to connect. Returns whether it did.
    pub async fn wait_connected(&self, timeout: Duration) -> bool {
        self.handle.wait_connected(timeout).await
    }

    /// The underlying bus actor handle, for reads, subscriptions and the domain
    /// operations in [`bussard_bus::ops`].
    pub fn handle(&self) -> &BusHandle {
        &self.handle
    }

    /// The resolved connection configuration.
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// The gateway as an operator reads it: `192.0.2.10:3671`, or
    /// `multicast 224.0.23.12:3671` for routing.
    pub fn gateway_display(&self) -> String {
        gateway_display(&self.config)
    }

    /// The send-sequence high-water mark of this service's secured group
    /// telegrams (issue #172).
    pub fn group_high_water(&self) -> &SequenceHighWater {
        &self.group_high_water
    }

    /// The policy this service was opened under.
    pub fn policy(&self) -> WritePolicy {
        self.policy
    }

    /// How the write gate passed: `None` for a read-only service,
    /// `Some(OptedIn)` when a non-loopback gateway was opted into (a surface
    /// should say so), `Some(Loopback)` otherwise.
    pub fn gate(&self) -> Option<WriteGate> {
        self.gate
    }

    /// Closes the bus connection, releasing the gateway's tunnel slot
    /// (issue #31). Best-effort: a gone actor is not an error.
    pub async fn close(&self) {
        let _ = self.handle.close().await;
    }

    /// The source address for a management session, checked against the bus
    /// unless `skip` (see [`SourcePolicy::Check`]).
    ///
    /// # Errors
    ///
    /// [`ServiceError::SourceCheck`] when a device answers at that address or
    /// the probe cannot run.
    pub async fn checked_source(&self, skip: bool) -> Result<IndividualAddress, ServiceError> {
        Ok(bussard_mgmt::checked_source(&self.handle, skip).await?)
    }

    /// Opens a management session to `target`: resolves the source, leases the
    /// bus, sends `T_Connect` (with the KNX Data Secure layer when a tool key is
    /// given) and authorizes as `options` say.
    ///
    /// The caller owns the returned session and must `disconnect` it. Prefer
    /// [`with_l4`](Self::with_l4), which does that on every path.
    ///
    /// # Errors
    ///
    /// The source check, the lease, the connect, or a required authorize.
    pub async fn connect_l4(
        &self,
        target: IndividualAddress,
        options: &L4Options,
    ) -> Result<Management, ServiceError> {
        let source = match options.source {
            SourcePolicy::Check { skip } => self.checked_source(skip).await?,
            SourcePolicy::Known(source) => source,
        };
        // A tunnel that is re-establishing itself (issue #177) is waited for
        // rather than raced: a T_Connect sent now would go stale.
        self.handle
            .wait_connected(self.handle.reconnect_budget())
            .await;
        let lease = self.handle.lease().await.map_err(ServiceError::Lease)?;
        let channel = LeaseChannel::new(lease);
        let secure = crate::secure::layer(&options.tool_key, &options.high_water);
        let mut l4 = Layer4Connection::connect_with_secure(
            channel,
            target,
            source,
            options.timeouts,
            secure,
        )
        .await?;
        match options.authorize {
            Authorize::Skip => {}
            Authorize::BestEffort(key) => {
                // Authorize as ETS does before configuration access; a device
                // without authorize, or one that denies, still serves reads.
                if let Err(err) = l4.authorize_or_fail(key).await {
                    tracing::debug!("{target} authorize did not grant: {err}");
                }
            }
            Authorize::Required(key) => {
                if let Err(err) = l4.authorize_or_fail(key).await {
                    let _ = l4.disconnect().await;
                    return Err(err.into());
                }
            }
        }
        Ok(l4)
    }

    /// [`connect_l4`](Self::connect_l4), re-run when a gateway link loss cut
    /// the connect short (issue #177).
    ///
    /// The connect is idempotent (a `T_Connect` and, when asked, an authorize),
    /// so it is retried up to [`CONNECT_ATTEMPTS`] times: on a lost-link
    /// transport error, or on a connection death while the bus reported a link
    /// loss. Each retry first waits for the bus to be connected again.
    async fn connect_l4_retrying(
        &self,
        target: IndividualAddress,
        options: &L4Options,
    ) -> Result<Management, ServiceError> {
        let mut attempt = 1u32;
        loop {
            let losses_before = self.handle.link_losses();
            match self.connect_l4(target, options).await {
                Ok(l4) => return Ok(l4),
                Err(ServiceError::Mgmt(err))
                    if attempt < CONNECT_ATTEMPTS
                        && lost_link(&err, self.handle.link_losses() != losses_before) =>
                {
                    attempt += 1;
                    tracing::warn!(
                        "connecting to {target} was interrupted by a gateway connection loss \
                         ({err}); retrying (attempt {attempt} of {CONNECT_ATTEMPTS})"
                    );
                    self.handle
                        .wait_connected(self.handle.reconnect_budget())
                        .await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Runs `body` inside a management session to `target` and disconnects on
    /// every path, returning the body's result.
    ///
    /// This is the Runtime / connect / lease / L4 / authorize / close skeleton
    /// that used to be copied into every `*_cmd.rs`. It does not close the bus
    /// itself: one bus usually outlives several sessions, so the surface calls
    /// [`close`](Self::close) when it is done.
    ///
    /// # Errors
    ///
    /// Whatever [`connect_l4`](Self::connect_l4) or `body` returns; a
    /// [`ServiceError`] converts into the caller's error type.
    pub async fn with_l4<T, E, F>(
        &self,
        target: IndividualAddress,
        options: &L4Options,
        body: F,
    ) -> Result<T, E>
    where
        F: AsyncFnOnce(&mut Management) -> Result<T, E>,
        E: From<ServiceError>,
    {
        let mut l4 = self.connect_l4_retrying(target, options).await?;
        let result = body(&mut l4).await;
        let _ = l4.disconnect().await;
        result
    }
}

/// How often [`BusService::with_l4`] opens its management session when a
/// gateway link loss interrupts the connect (issue #177).
pub const CONNECT_ATTEMPTS: u32 = 3;

/// Whether `err` from a management connect means the gateway link dropped: a
/// lost-link transport error, or a connection death while the bus reported a
/// link loss (`link_lost`).
fn lost_link(err: &MgmtError, link_lost: bool) -> bool {
    match err {
        MgmtError::Transport(e) => e.is_link_loss(),
        MgmtError::NoResponse { .. }
        | MgmtError::Disconnected { .. }
        | MgmtError::MidSessionSilence { .. } => link_lost,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_transport::TransportError;

    #[test]
    fn test_lost_link_classifies_connect_errors() -> Result<(), Box<dyn std::error::Error>> {
        let address: IndividualAddress = "1.1.4".parse()?;
        let timeout = MgmtError::Transport(TransportError::Timeout("TUNNELING_ACK"));
        assert!(lost_link(&timeout, false));
        // A silent device is only a link loss when the bus saw one.
        let silent = MgmtError::NoResponse { address };
        assert!(!lost_link(&silent, false));
        assert!(lost_link(&silent, true));
        // Refusals and closed connections are never retried.
        assert!(!lost_link(
            &MgmtError::AccessDenied { address, level: 2 },
            true
        ));
        assert!(!lost_link(
            &MgmtError::Transport(TransportError::Closed),
            true
        ));
        Ok(())
    }
}
