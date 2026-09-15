//! An in-memory ring buffer of recent telegrams with a wait-for primitive.
//!
//! [`TelegramRing`] holds the most recent decoded telegrams in a bounded deque
//! (older ones are evicted) and lets callers:
//!
//! - push new telegrams (from the live stream),
//! - query the buffer by [`Filter`], and
//! - `await` the next telegram matching a filter, with a timeout.
//!
//! The MCP tools `knx_recent_telegrams` and `knx_wait_for_telegram` sit
//! directly on this, which is why it lives in `bussard-monitor` and not in the
//! MCP crate — the CLI and MCP share one buffer.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_transport::cemi::MessageCode;
use tokio::sync::broadcast;

use crate::decode::DecodedTelegram;
use crate::filter::Filter;

/// The default ring capacity.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// A telegram as broadcast to waiters: the decoded telegram plus the cEMI
/// message code it arrived with.
///
/// The message code distinguishes a real bus indication (`L_Data.ind`) from the
/// gateway's local confirmation echo of our own request (`L_Data.con`) — the
/// echo carries the same GA and APCI as the request, so a GA-only wait would
/// match it and report the echo as the device's answer (issue #32).
#[derive(Debug, Clone)]
pub struct RingEvent {
    /// The decoded telegram.
    pub telegram: DecodedTelegram,
    /// The cEMI message code of the frame that produced it.
    pub message_code: MessageCode,
}

/// A bounded, shareable ring buffer of recent telegrams.
///
/// Cloning a `TelegramRing` yields another handle onto the *same* buffer, so a
/// producer task and multiple consumers can share it cheaply.
#[derive(Clone)]
pub struct TelegramRing {
    inner: Arc<Mutex<VecDeque<DecodedTelegram>>>,
    capacity: usize,
    // A broadcast channel wakes waiters on each push. The payload carries the
    // telegram itself so waiters need not re-lock the buffer.
    tx: broadcast::Sender<RingEvent>,
}

impl TelegramRing {
    /// Creates a ring holding up to `DEFAULT_CAPACITY` telegrams.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Creates a ring holding up to `capacity` telegrams (minimum 1).
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        // The broadcast buffer need not match the ring size; a modest depth is
        // enough since waiters consume promptly and lag is tolerated.
        let (tx, _rx) = broadcast::channel(1024.min(capacity).max(16));
        TelegramRing {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
            tx,
        }
    }

    /// Pushes a telegram, evicting the oldest if the buffer is full, and wakes
    /// any waiters.
    ///
    /// The message code defaults to `L_Data.ind` (a bus indication); producers
    /// that see the raw frame should prefer
    /// [`push_with_code`](TelegramRing::push_with_code) so waiters can tell a
    /// gateway con-echo apart from a real indication.
    pub fn push(&self, telegram: DecodedTelegram) {
        self.push_with_code(telegram, MessageCode::LDataInd);
    }

    /// Pushes a telegram together with the cEMI message code of the frame it
    /// came from, evicting the oldest if the buffer is full, and wakes any
    /// waiters.
    pub fn push_with_code(&self, telegram: DecodedTelegram, message_code: MessageCode) {
        {
            let mut buf = self.lock();
            if buf.len() == self.capacity {
                buf.pop_front();
            }
            buf.push_back(telegram.clone());
        }
        // Ignore send errors: no active receivers is fine.
        let _ = self.tx.send(RingEvent {
            telegram,
            message_code,
        });
    }

    /// Subscribes to future pushes, returning a [`RingSubscription`].
    ///
    /// The subscription exists from the moment this returns, so a caller can
    /// subscribe **before** transmitting a request and then await the response —
    /// closing the race where a `wait_for` spawned as a task only subscribed on
    /// its first poll and could miss a fast answer (issue #32).
    pub fn subscribe(&self) -> RingSubscription {
        RingSubscription {
            rx: self.tx.subscribe(),
        }
    }

    /// The number of telegrams currently buffered.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Returns up to `limit` most-recent telegrams matching `filter`, newest
    /// first. A `limit` of `None` returns all matches.
    pub fn recent(&self, filter: &Filter, limit: Option<usize>) -> Vec<DecodedTelegram> {
        let buf = self.lock();
        let mut out: Vec<DecodedTelegram> = buf
            .iter()
            .rev()
            .filter(|t| filter.matches(t))
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect();
        out.shrink_to_fit();
        out
    }

    /// Waits for the next telegram matching `filter`, up to `timeout`.
    ///
    /// Returns `Some(telegram)` on a match, or `None` if the timeout elapses
    /// first. Only telegrams pushed *after* the call are considered (this is a
    /// "press the button now" primitive); check [`recent`](TelegramRing::recent)
    /// first if an already-seen telegram would satisfy the caller.
    ///
    /// The subscription is created when this is *called*, but if the call site
    /// spawns the future as a task, subscription only happens once the task
    /// first runs. Callers that must not miss a fast response should use
    /// [`subscribe`](TelegramRing::subscribe) before sending instead.
    pub async fn wait_for(&self, filter: &Filter, timeout: Duration) -> Option<DecodedTelegram> {
        self.subscribe()
            .wait_for_matching(timeout, |t, _code| filter.matches(t))
            .await
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<DecodedTelegram>> {
        // The mutex is only poisoned if a holder panicked; recover the guard so
        // a single panicked push cannot wedge the whole monitor.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A live subscription to a [`TelegramRing`]'s pushes.
///
/// Created by [`TelegramRing::subscribe`]. Telegrams pushed after creation are
/// buffered (up to the broadcast depth) even before the first `await`, so
/// subscribing before transmitting a request guarantees the response is seen.
pub struct RingSubscription {
    rx: broadcast::Receiver<RingEvent>,
}

impl RingSubscription {
    /// Waits for the next telegram for which `matches(telegram, message_code)`
    /// returns `true`, up to `timeout`.
    ///
    /// Returns `Some(telegram)` on a match, or `None` if the timeout elapses or
    /// the ring is gone. Non-matching telegrams are skipped; a lagged receiver
    /// (missed pushes under burst) keeps waiting on fresh ones.
    pub async fn wait_for_matching(
        &mut self,
        timeout: Duration,
        matches: impl Fn(&DecodedTelegram, MessageCode) -> bool,
    ) -> Option<DecodedTelegram> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, self.rx.recv()).await {
                // A matching telegram arrived.
                Ok(Ok(ev)) if matches(&ev.telegram, ev.message_code) => return Some(ev.telegram),
                // A non-matching telegram: keep waiting.
                Ok(Ok(_)) => continue,
                // Lagged (we missed some): keep waiting on fresh ones.
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                // Sender dropped: no more telegrams will arrive.
                Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                // Timed out.
                Err(_) => return None,
            }
        }
    }
}

impl Default for TelegramRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use bussard_model::codec::TypedValue;
    use bussard_model::{GroupAddress, IndividualAddress};

    use crate::decode::{ApciKind, DestinationRef};

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }
    fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }

    fn tel(dest: &str) -> DecodedTelegram {
        DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH,
            source: ia("1.1.1"),
            source_name: None,
            destination: DestinationRef::Group(ga(dest)),
            destination_name: None,
            apci: ApciKind::Write,
            payload: vec![1],
            value: Some(TypedValue::Raw(vec![1])),
            dpt: None,
            object_name: None,
            decode_note: None,
        }
    }

    #[test]
    fn fills_and_evicts() {
        let ring = TelegramRing::with_capacity(3);
        for i in 0..5u8 {
            ring.push(tel(&format!("1/0/{i}")));
        }
        assert_eq!(ring.len(), 3);
        // Newest first: 1/0/4, 1/0/3, 1/0/2.
        let recent = ring.recent(&Filter::default(), None);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].destination.to_string(), "1/0/4");
        assert_eq!(recent[2].destination.to_string(), "1/0/2");
    }

    #[test]
    fn recent_filters_and_limits() {
        let ring = TelegramRing::with_capacity(10);
        ring.push(tel("3/2/0"));
        ring.push(tel("4/0/0"));
        ring.push(tel("3/2/1"));

        let f = Filter::parse("3/").unwrap();
        let all = ring.recent(&f, None);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].destination.to_string(), "3/2/1");

        let limited = ring.recent(&f, Some(1));
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].destination.to_string(), "3/2/1");
    }

    #[tokio::test]
    async fn wait_for_times_out() {
        let ring = TelegramRing::with_capacity(10);
        let got = ring
            .wait_for(&Filter::default(), Duration::from_millis(50))
            .await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn subscription_buffers_pushes_before_first_await() {
        // Issue #32 (waiter race): a subscription taken before the send must see
        // a telegram pushed before the waiter is first polled.
        let ring = TelegramRing::with_capacity(10);
        let mut sub = ring.subscribe();
        // Push BEFORE awaiting: the broadcast buffers it for the subscription.
        ring.push(tel("3/2/0"));
        let got = sub
            .wait_for_matching(Duration::from_millis(200), |t, _| {
                t.destination.to_string() == "3/2/0"
            })
            .await
            .expect("the pre-await push must be delivered");
        assert_eq!(got.destination.to_string(), "3/2/0");
    }

    #[tokio::test]
    async fn predicate_wait_skips_con_echo() {
        // Issue #32 (echo-skip): the gateway's L_Data.con echo of our own
        // request must be skipped; the L_Data.ind response is the answer.
        let ring = TelegramRing::with_capacity(10);
        let mut sub = ring.subscribe();
        // The con echo arrives first (same GA), then the real indication.
        ring.push_with_code(tel("3/2/0"), MessageCode::LDataCon);
        ring.push_with_code(tel("3/2/0"), MessageCode::LDataInd);
        let got = sub
            .wait_for_matching(Duration::from_millis(200), |t, code| {
                t.destination.to_string() == "3/2/0" && code != MessageCode::LDataCon
            })
            .await
            .expect("the indication must be delivered");
        assert_eq!(got.destination.to_string(), "3/2/0");
    }

    #[tokio::test]
    async fn wait_for_matches() {
        let ring = TelegramRing::with_capacity(10);
        let ring2 = ring.clone();
        // Push a matching telegram shortly after the wait begins.
        let pusher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            ring2.push(tel("9/1/9")); // non-matching, should be skipped
            ring2.push(tel("3/2/0")); // matching
        });
        let f = Filter::parse("3/2/0").unwrap();
        let got = ring
            .wait_for(&f, Duration::from_secs(2))
            .await
            .expect("should get the matching telegram");
        assert_eq!(got.destination.to_string(), "3/2/0");
        pusher.await.unwrap();
    }
}
