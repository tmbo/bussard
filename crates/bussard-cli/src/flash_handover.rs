//! The flash pre-flight's connection, handed to the write phase under `--yes`
//! (issue #213).
//!
//! Without `--yes` the confirmation prompt sits between the read-only
//! pre-flight and the write phase, and a device drops a Layer-4 connection
//! that stays silent for 6 s, so the pre-flight disconnects and the write
//! phase opens its own connection (seeded with what the pre-flight learned).
//! Under `--yes` nothing waits between the two phases: the pre-flight keeps
//! its connection here and the write phase takes it over, which saves a
//! `T_Disconnect`, a `T_Connect`, the Data Secure `S-A_Sync` and the
//! `A_Authorize_Request`.
//!
//! The connection holds the bus's exclusive Layer-4 lease while it is kept, so
//! nothing else may open a management connection until it is taken or
//! released. Every exit path releases it: [`Handover`] sends the
//! `T_Disconnect` when it is dropped with the connection still inside.

use std::time::{Duration, Instant};

use bussard_service::Management;

/// How long a kept connection may sit idle before the write phase would rather
/// open a fresh one.
///
/// A KNX device closes a connection-oriented Layer-4 connection after 6 s
/// without a telegram (the transport layer's connection timeout, KNX Standard
/// 3/3/4; the same 6 s the flash pre-flight already plans around, see
/// `flash_cmd::run`). Half of it leaves the first write-phase request a margin
/// of 3 s, far more than one request takes (about 0.2 s per request on the
/// reference installation, speed deep dive 2026-09-24). An older connection is
/// disconnected and the write phase reconnects, the behaviour before #213.
pub(crate) const HANDOVER_IDLE_LIMIT: Duration = Duration::from_secs(3);

/// Environment variable that switches the hand-over off: set to `1`, the
/// pre-flight disconnects and the write phase opens its own connection even
/// under `--yes`, the behaviour before issue #213. A diagnostic and campaign
/// switch, like `BUSSARD_FLASH_RECONNECT_EXCHANGES`; the mock tests use it to
/// compare both paths against the same device.
pub(crate) const NO_HANDOVER_ENV: &str = "BUSSARD_FLASH_NO_HANDOVER";

/// Whether the pre-flight may keep its connection for the write phase: only
/// under `--yes`, and not when [`NO_HANDOVER_ENV`] is `1`.
pub(crate) fn wanted(yes: bool) -> bool {
    yes && bussard_model::dotenv::var(NO_HANDOVER_ENV)
        .ok()
        .as_deref()
        .map(str::trim)
        != Some("1")
}

/// The pre-flight connection kept for the write phase, if any.
pub(crate) struct Handover<'r> {
    /// The runtime the command runs on, for the `T_Disconnect` of a connection
    /// that is not taken.
    runtime: &'r tokio::runtime::Runtime,
    /// The kept connection and when the pre-flight last used it.
    kept: Option<(Management, Instant)>,
}

impl<'r> Handover<'r> {
    /// No connection kept yet.
    pub(crate) fn new(runtime: &'r tokio::runtime::Runtime) -> Handover<'r> {
        Handover {
            runtime,
            kept: None,
        }
    }

    /// Keeps `l4`, whose last request has just completed, for the write phase.
    /// A connection kept earlier is released first.
    pub(crate) fn keep(&mut self, l4: Management) {
        self.release();
        self.kept = Some((l4, Instant::now()));
    }

    /// Takes the kept connection for the write phase, or `None` when there is
    /// none, when it is known to be closed, or when it sat idle longer than
    /// [`HANDOVER_IDLE_LIMIT`]; the last two are disconnected and the write
    /// phase opens a fresh connection instead.
    ///
    /// Must be called outside the runtime (it may block on the disconnect).
    pub(crate) fn take(&mut self) -> Option<Management> {
        let (l4, since) = self.kept.take()?;
        let idle = since.elapsed();
        if idle <= HANDOVER_IDLE_LIMIT && !l4.is_closed() {
            tracing::debug!(
                "{}: the write phase takes over the pre-flight connection (idle {} ms)",
                l4.target(),
                idle.as_millis()
            );
            return Some(l4);
        }
        tracing::debug!(
            "{}: the pre-flight connection is closed or was idle {} ms; reconnecting",
            l4.target(),
            idle.as_millis()
        );
        let _ = self.runtime.block_on(l4.disconnect());
        None
    }

    /// Disconnects the kept connection, if any, so the bus lease is free for
    /// another session.
    ///
    /// Must be called outside the runtime (it blocks on the disconnect).
    pub(crate) fn release(&mut self) {
        if let Some((l4, _)) = self.kept.take() {
            let _ = self.runtime.block_on(l4.disconnect());
        }
    }
}

impl Drop for Handover<'_> {
    fn drop(&mut self) {
        self.release();
    }
}
