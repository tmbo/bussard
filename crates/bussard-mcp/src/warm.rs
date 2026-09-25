//! The warm management connection of the MCP server (issue #215).
//!
//! An assistant often asks about one device several times in a row
//! (`knx_describe_device`, then again after a model edit). Each call used to
//! open its own Layer-4 connection: `T_Connect`, the Data Secure `S-A_Sync`,
//! `A_Authorize_Request` and the max-APDU read, then `T_Disconnect`. The
//! server now keeps the last connection for a short idle window and hands it
//! to the next call to the same device.
//!
//! The rules:
//!
//! - **One device at a time.** Every management call holds the slot's lock for
//!   its whole session, so two calls never talk to devices at once, and a call
//!   to another device (or one that opens its own lease, like the programming
//!   tier) disconnects the kept connection first. The bus lease the kept
//!   connection holds is never contended.
//! - **Idle close.** A kept connection is disconnected once it has been idle
//!   for [`WARM_IDLE_LIMIT`], well before the device's own 6 s timeout closes
//!   it, and a call that finds it older opens a fresh one.
//! - **Tunnel re-establishment unchanged.** A kept connection is used only if
//!   the bus has not lost its gateway link since (the link-loss count of
//!   #177/#192 is unchanged); after a loss the tunnel is new and the call
//!   reconnects as before.
//! - **Fallback.** A call that fails on a reused connection is repeated once on
//!   a fresh one (see `knx_describe_device`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use bussard_model::IndividualAddress;
use bussard_service::Management;
use tokio::sync::{Mutex, MutexGuard};

/// How long a kept connection may sit idle before it is closed.
///
/// A KNX device closes a connection-oriented Layer-4 connection after 6 s
/// without a telegram (the transport layer's connection timeout, KNX Standard
/// 3/3/4; the same window `bussard flash` plans around). Half of it leaves the
/// next call's first request a margin of 3 s, far more than one request takes
/// (about 0.2 s on the reference installation, speed deep dive 2026-09-24).
pub const WARM_IDLE_LIMIT: Duration = Duration::from_secs(3);

/// A kept connection and what it was opened for.
struct Kept {
    /// The device it is connected to.
    target: IndividualAddress,
    /// Whether it wraps management APDUs with a Data Secure tool key.
    secure: bool,
    /// The bus's link-loss count when it was kept.
    link_losses: u64,
    /// When its last request completed.
    last_used: Instant,
    /// Which keep this is, so a stale idle-close timer leaves a newer one alone.
    generation: u64,
    /// The connection.
    l4: Management,
}

/// The slot behind the lock.
#[derive(Default)]
struct Slot {
    kept: Option<Kept>,
    generation: u64,
}

/// The server's single warm management connection. Cloning shares it.
#[derive(Clone, Default)]
pub struct WarmConnection {
    slot: Arc<Mutex<Slot>>,
}

impl WarmConnection {
    /// An empty slot.
    pub fn new() -> WarmConnection {
        WarmConnection::default()
    }

    /// Locks the slot for one management call. Hold the guard for the whole
    /// session: it is what keeps management calls sequential.
    pub async fn lock(&self) -> WarmGuard<'_> {
        WarmGuard {
            slot: self.slot.lock().await,
            owner: self,
        }
    }
}

/// One management call's hold on the warm slot.
pub struct WarmGuard<'a> {
    slot: MutexGuard<'a, Slot>,
    owner: &'a WarmConnection,
}

impl WarmGuard<'_> {
    /// Takes the kept connection when it is to `target`, of the same security,
    /// idle no longer than [`WARM_IDLE_LIMIT`], still open, and no gateway link
    /// was lost since (`link_losses` is the bus's current count). Anything else
    /// kept is disconnected. The slot is empty afterwards either way.
    pub async fn take(
        &mut self,
        target: IndividualAddress,
        secure: bool,
        link_losses: u64,
    ) -> Option<Management> {
        let kept = self.slot.kept.take()?;
        let usable = kept.target == target
            && kept.secure == secure
            && kept.link_losses == link_losses
            && kept.last_used.elapsed() <= WARM_IDLE_LIMIT
            && !kept.l4.is_closed();
        if usable {
            tracing::debug!("{target}: reusing the warm management connection");
            return Some(kept.l4);
        }
        let _ = kept.l4.disconnect().await;
        None
    }

    /// Disconnects the kept connection, if any, so the bus lease is free.
    pub async fn release(&mut self) {
        if let Some(kept) = self.slot.kept.take() {
            let _ = kept.l4.disconnect().await;
        }
    }

    /// Keeps `l4`, whose last request has just completed, for the next call,
    /// and schedules its idle close. A closed connection is not kept.
    pub fn keep(
        &mut self,
        l4: Management,
        target: IndividualAddress,
        secure: bool,
        link_losses: u64,
    ) {
        if l4.is_closed() {
            return;
        }
        self.slot.generation += 1;
        let generation = self.slot.generation;
        self.slot.kept = Some(Kept {
            target,
            secure,
            link_losses,
            last_used: Instant::now(),
            generation,
            l4,
        });
        let slot = Arc::clone(&self.owner.slot);
        tokio::spawn(async move {
            tokio::time::sleep(WARM_IDLE_LIMIT).await;
            let mut slot = slot.lock().await;
            if slot
                .kept
                .as_ref()
                .is_some_and(|kept| kept.generation == generation)
                && let Some(kept) = slot.kept.take()
            {
                tracing::debug!("{}: closing the idle warm connection", kept.target);
                let _ = kept.l4.disconnect().await;
            }
        });
    }
}
