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

use tokio::sync::broadcast;

use crate::decode::DecodedTelegram;
use crate::filter::Filter;

/// The default ring capacity.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// A bounded, shareable ring buffer of recent telegrams.
///
/// Cloning a `TelegramRing` yields another handle onto the *same* buffer, so a
/// producer task and multiple consumers can share it cheaply.
#[derive(Clone)]
pub struct TelegramRing {
    inner: Arc<Mutex<VecDeque<DecodedTelegram>>>,
    capacity: usize,
    // A broadcast channel wakes `wait_for` callers on each push. The payload is
    // the telegram itself so waiters need not re-lock the buffer.
    tx: broadcast::Sender<DecodedTelegram>,
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
    /// any [`wait_for`](TelegramRing::wait_for) callers.
    pub fn push(&self, telegram: DecodedTelegram) {
        {
            let mut buf = self.lock();
            if buf.len() == self.capacity {
                buf.pop_front();
            }
            buf.push_back(telegram.clone());
        }
        // Ignore send errors: no active receivers is fine.
        let _ = self.tx.send(telegram);
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
    pub async fn wait_for(&self, filter: &Filter, timeout: Duration) -> Option<DecodedTelegram> {
        let mut rx = self.tx.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                // A matching telegram arrived.
                Ok(Ok(t)) if filter.matches(&t) => return Some(t),
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

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<DecodedTelegram>> {
        // The mutex is only poisoned if a holder panicked; recover the guard so
        // a single panicked push cannot wedge the whole monitor.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
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
