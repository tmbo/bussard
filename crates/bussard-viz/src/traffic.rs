//! The traffic hub: a sequenced telegram backlog + broadcast, plus the derived
//! per-GA state map, fed by a background task subscribed to the bus.
//!
//! [`TrafficHub`] gives the SSE endpoint what a raw [`TelegramRing`] cannot: a
//! monotonic `seq` on every telegram and a bounded backlog that a late
//! subscriber can replay from without duplicates or gaps (SSE `Last-Event-ID`).
//!
//! The [`feed`] task copies the bus-subscription pattern from the MCP runner:
//! subscribe to the [`BusHandle`], decode each inbound frame against the model,
//! and publish it through the hub. It also awaits `handle.state_changes()` and
//! emits a `bus` event whenever the connection state changes, and updates the
//! per-GA state map from Write/Response telegrams on group destinations.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bussard_bus::{BusHandle, BusState, ops};
use bussard_mgmt::LeaseChannel;
use bussard_mgmt::broadcast::devices_in_programming_mode_within;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_monitor::decode::{ApciKind, DestinationRef};
use bussard_monitor::{DecodedTelegram, json_value};
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::state::{BusStatus, ModelHandle};

/// How often the programming-mode watch probes the bus with a broadcast
/// `A_IndividualAddress_Read`. Chosen so the red-prog-LED highlight tracks a
/// button press within a couple of seconds without flooding the bus.
pub const PROG_PROBE_INTERVAL: Duration = Duration::from_secs(3);

/// The per-probe window for collecting `A_IndividualAddress_Response` frames.
/// Mirrors the assign flow's collection window: a device in programming mode
/// answers within a fraction of a second, so ~1s is ample.
pub const PROG_COLLECTION_WINDOW: Duration = Duration::from_secs(1);

/// The depth of the SSE broadcast channel. A subscriber that falls this far
/// behind receives a `gap` event and must reconcile via a fresh snapshot.
const BROADCAST_DEPTH: usize = 1024;

/// The maximum number of telegrams retained in the replay backlog.
const BACKLOG_CAP: usize = 1000;

/// A single hub event, tagged for the SSE `event:` field.
///
/// [`HubEvent::Telegram`] carries the `json_value` projection extended with its
/// `seq`; [`HubEvent::Bus`] carries a bus-status object; [`HubEvent::Gap`]
/// signals broadcast lag (the receiver missed events and should re-snapshot).
#[derive(Debug, Clone)]
pub enum HubEvent {
    /// A decoded telegram with its monotonic sequence id.
    Telegram {
        /// The monotonic sequence id (the SSE `id:`).
        seq: u64,
        /// The `json_value` projection plus a `seq` field.
        data: Value,
    },
    /// A bus connection-state change (also emitted once at subscribe time).
    Bus(Value),
    /// A model reload: the model was swapped, so connected pages should refetch
    /// `/api/model`. Carries `{ "model_version": N, "stats": { … } }`.
    Model(Value),
    /// The observed programming-mode set CHANGED. Carries
    /// `{ "devices": ["1.1.2", …] }` — the current set of individual addresses
    /// answering the broadcast `A_IndividualAddress_Read`. Emitted only on a
    /// change (including back to empty), never on every probe tick.
    Prog(Value),
    /// A broadcast-lag signal: the subscriber missed `count` events.
    Gap {
        /// How many broadcast messages were skipped.
        count: u64,
    },
    /// Server shutdown: every SSE stream ends on receipt so axum's graceful
    /// shutdown is not held open forever by never-ending event streams.
    Shutdown,
}

/// The last observed state of a single group address, for the state endpoint.
#[derive(Debug, Clone)]
struct GaState {
    value: Option<String>,
    payload: String,
    dpt: Option<String>,
    apci: &'static str,
    ts_utc: String,
    source: String,
    source_name: Option<String>,
    seq: u64,
}

impl GaState {
    /// Projects the GA state to its JSON object.
    fn to_json(&self) -> Value {
        json!({
            "value": self.value,
            "payload": self.payload,
            "dpt": self.dpt,
            "apci": self.apci,
            "ts_utc": self.ts_utc,
            "source": self.source,
            "source_name": self.source_name,
            "seq": self.seq,
        })
    }
}

/// The sequenced backlog + broadcast hub for live telegrams and bus events.
///
/// Cloning is cheap (everything is behind `Arc`). A subscriber calls
/// [`TrafficHub::subscribe`] to get a broadcast receiver, then
/// [`TrafficHub::backlog_since`] for a race-free replay snapshot (subscribe
/// first, then snapshot, then drop events at or below the snapshot's max seq).
#[derive(Clone)]
pub struct TrafficHub {
    inner: Arc<Inner>,
}

/// The shared hub state behind an `Arc`.
struct Inner {
    /// The monotonic sequence counter and the bounded backlog, together under
    /// one lock so a telegram's seq assignment and its push are atomic.
    backlog: Mutex<Backlog>,
    /// The broadcast sender fanning events out to SSE subscribers.
    tx: broadcast::Sender<HubEvent>,
    /// The last value seen per group address, for `GET /api/state`.
    ga_state: RwLock<BTreeMap<GroupAddress, GaState>>,
    /// The individual addresses currently observed in programming mode, for
    /// `GET /api/state`. Empty when none are, or when the watch is disabled
    /// (the watch never runs, so the set stays empty).
    prog: RwLock<BTreeSet<IndividualAddress>>,
}

/// The sequence counter and the retained telegram backlog.
struct Backlog {
    /// The seq to assign to the next telegram (starts at 1).
    next_seq: u64,
    /// The retained telegrams, each as `(seq, json_value+seq)`, capped at
    /// [`BACKLOG_CAP`] (oldest evicted first).
    entries: VecDeque<(u64, Value)>,
}

impl Default for TrafficHub {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficHub {
    /// Creates an empty hub with a fresh sequence counter.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(BROADCAST_DEPTH);
        TrafficHub {
            inner: Arc::new(Inner {
                backlog: Mutex::new(Backlog {
                    next_seq: 1,
                    entries: VecDeque::with_capacity(BACKLOG_CAP),
                }),
                tx,
                ga_state: RwLock::new(BTreeMap::new()),
                prog: RwLock::new(BTreeSet::new()),
            }),
        }
    }

    /// Subscribes to the live event broadcast.
    ///
    /// Subscribe *before* calling [`backlog_since`](Self::backlog_since) so no
    /// telegram can slip between the snapshot and the subscription.
    pub fn subscribe(&self) -> broadcast::Receiver<HubEvent> {
        self.inner.tx.subscribe()
    }

    /// Publishes a decoded telegram: assigns it a seq, appends it to the
    /// backlog (evicting the oldest if full), updates the GA state, and
    /// broadcasts it. Returns the assigned seq.
    pub fn publish(&self, telegram: &DecodedTelegram) -> u64 {
        let mut data = json_value(telegram);

        let seq = {
            // Lock is poisoned only if a previous holder panicked while mutating;
            // recover the guard so a single panic does not wedge the hub.
            let mut backlog = self.inner.backlog.lock().unwrap_or_else(|p| p.into_inner());
            let seq = backlog.next_seq;
            backlog.next_seq += 1;
            if let Value::Object(map) = &mut data {
                map.insert("seq".to_string(), Value::from(seq));
            }
            backlog.entries.push_back((seq, data.clone()));
            while backlog.entries.len() > BACKLOG_CAP {
                backlog.entries.pop_front();
            }
            seq
        };

        self.update_ga_state(telegram, seq);

        // A send with no subscribers returns Err; that is expected and fine.
        let _ = self.inner.tx.send(HubEvent::Telegram { seq, data });
        seq
    }

    /// Broadcasts a bus-status change event (no seq; not backlogged).
    pub fn publish_bus(&self, status: Value) {
        let _ = self.inner.tx.send(HubEvent::Bus(status));
    }

    /// Broadcasts a model-reload event (no seq; not backlogged) so connected
    /// pages refetch `/api/model`. `data` is `{ "model_version", "stats" }`.
    pub fn publish_model(&self, data: Value) {
        let _ = self.inner.tx.send(HubEvent::Model(data));
    }

    /// The current programming-mode set as a JSON array of IA strings, for
    /// `GET /api/state`'s `prog` field. Empty when none are observed or the
    /// watch is disabled.
    pub fn prog_values(&self) -> Value {
        let set = self.inner.prog.read().unwrap_or_else(|p| p.into_inner());
        Value::Array(set.iter().map(|ia| Value::from(ia.to_string())).collect())
    }

    /// Replaces the observed programming-mode set with `next`. If it differs
    /// from the previous set, stores it and broadcasts a [`HubEvent::Prog`]
    /// carrying the new set, then returns `true`. On no change, does nothing and
    /// returns `false` (so the watch publishes only on a genuine transition).
    pub fn set_prog_if_changed(&self, next: BTreeSet<IndividualAddress>) -> bool {
        {
            let current = self.inner.prog.read().unwrap_or_else(|p| p.into_inner());
            if *current == next {
                return false;
            }
        }
        let devices: Vec<Value> = next.iter().map(|ia| Value::from(ia.to_string())).collect();
        {
            let mut current = self.inner.prog.write().unwrap_or_else(|p| p.into_inner());
            *current = next;
        }
        let _ = self
            .inner
            .tx
            .send(HubEvent::Prog(json!({ "devices": devices })));
        true
    }

    /// Broadcasts [`HubEvent::Shutdown`], ending every live SSE stream.
    ///
    /// Called on Ctrl-C before axum's graceful shutdown: without it, open
    /// `/api/traffic` connections are never-ending in-flight requests that
    /// keep the graceful shutdown waiting forever.
    pub fn shutdown(&self) {
        let _ = self.inner.tx.send(HubEvent::Shutdown);
    }

    /// Returns the backlog entries with `seq > after`, up to `limit` of the most
    /// recent, oldest-first, along with the current maximum seq.
    ///
    /// A subscriber that just subscribed calls this to replay: it skips any live
    /// broadcast event whose seq is `<= max` (those are already in this
    /// snapshot), giving a gap-free, duplicate-free stream.
    pub fn backlog_since(&self, after: u64, limit: usize) -> (Vec<Value>, u64) {
        let backlog = self.inner.backlog.lock().unwrap_or_else(|p| p.into_inner());
        let max = backlog.next_seq.saturating_sub(1);
        // Filter to seq > after, then keep the newest `limit`.
        let mut kept: Vec<Value> = backlog
            .entries
            .iter()
            .filter(|(seq, _)| *seq > after)
            .map(|(_, v)| v.clone())
            .collect();
        if kept.len() > limit {
            let drop = kept.len() - limit;
            kept.drain(0..drop);
        }
        (kept, max)
    }

    /// The current maximum assigned seq (0 if none yet).
    pub fn current_seq(&self) -> u64 {
        let backlog = self.inner.backlog.lock().unwrap_or_else(|p| p.into_inner());
        backlog.next_seq.saturating_sub(1)
    }

    /// The per-GA `values` object for `GET /api/state`, keyed by group address.
    pub fn state_values(&self) -> Value {
        let map = self
            .inner
            .ga_state
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let mut obj = serde_json::Map::new();
        for (ga, st) in map.iter() {
            obj.insert(ga.to_string(), st.to_json());
        }
        Value::Object(obj)
    }

    /// Updates the per-GA state from a Write or Response telegram on a group
    /// destination. Reads and management traffic do not update state.
    fn update_ga_state(&self, t: &DecodedTelegram, seq: u64) {
        let DestinationRef::Group(ga) = t.destination else {
            return;
        };
        if !matches!(t.apci, ApciKind::Write | ApciKind::Response) {
            return;
        }
        let mut payload_hex = String::with_capacity(t.payload.len() * 2);
        for b in &t.payload {
            use std::fmt::Write;
            let _ = write!(payload_hex, "{b:02x}");
        }
        let st = GaState {
            value: t.value.as_ref().map(|v| v.to_string()),
            payload: payload_hex,
            dpt: t.dpt.map(|d| d.to_string()),
            apci: t.apci.tag(),
            ts_utc: bussard_monitor::timefmt::to_rfc3339(t.timestamp),
            source: t.source.to_string(),
            source_name: t.source_name.clone(),
            seq,
        };
        let mut map = self
            .inner
            .ga_state
            .write()
            .unwrap_or_else(|p| p.into_inner());
        map.insert(ga, st);
    }
}

/// Feeds the hub from a live bus subscription until the actor shuts down.
///
/// Mirrors the MCP runner's feeder: subscribe to the bus, decode every inbound
/// frame against the model, and publish it. In parallel it awaits the bus
/// [`state_changes`](BusHandle::state_changes) watch and, on every transition,
/// republishes the status as a `bus` event so the UI badge updates immediately
/// without a client round-trip or a polling tick.
///
/// This runs only when a bus is configured (the caller does not spawn it in
/// model-only mode). The `bus` event on SSE connect is emitted independently by
/// the SSE handler, so it does not depend on this task ever having run.
///
/// Name resolution reads the model through the [`ModelHandle`] on each frame, so
/// a `POST /api/reload` swap is reflected in the very next decoded telegram
/// without restarting the feeder.
pub async fn feed(hub: TrafficHub, handle: BusHandle, model: ModelHandle, status: BusStatus) {
    let mut sub = handle.subscribe();
    let mut states = handle.state_changes();
    // Mark the state present at startup as already seen: the SSE handler emits
    // the initial `bus` event on connect, so the feeder only publishes genuine
    // transitions from here on.
    let mut last_state: BusState = *states.borrow_and_update();

    loop {
        tokio::select! {
            inbound = sub.recv() => {
                match inbound {
                    Some(frame) => {
                        // Read the current model per frame so a reload swap is
                        // picked up immediately for name resolution.
                        let snapshot = model.current();
                        let decoded = DecodedTelegram::from_frame(
                            &frame.frame,
                            Some(snapshot.model.as_ref()),
                        );
                        hub.publish(&decoded);
                    }
                    // The actor shut down; stop feeding.
                    None => break,
                }
            }
            changed = states.changed() => {
                if changed.is_err() {
                    // The actor dropped its sender; stop feeding.
                    break;
                }
                let now = *states.borrow_and_update();
                if now != last_state {
                    last_state = now;
                    hub.publish_bus(status.to_json());
                }
            }
        }
    }
}

/// Probes the bus for devices in programming mode on a fixed cadence, updating
/// the hub's programming-mode set and emitting a `prog` event on every change.
///
/// This runs only when `bussard viz --watch-prog` is set: the probe puts a
/// broadcast `A_IndividualAddress_Read` on the bus every [`PROG_PROBE_INTERVAL`],
/// which is active traffic and must never happen unnoticed against a real
/// installation. Each probe leases the shared bus (the same lease `assign` uses)
/// so it never opens a second tunnel, collects responders for
/// [`PROG_COLLECTION_WINDOW`], and diffs the responding-IA set against the last
/// one via [`TrafficHub::set_prog_if_changed`].
///
/// Connection state is respected: probes are skipped while the bus is not
/// connected, and the observed set is cleared (emitting a change if it was
/// non-empty) on a drop, so a stale highlight never lingers after the gateway
/// goes away. When the bus reconnects, probing resumes.
///
/// The task loops until the actor shuts down (a lease error) or the caller
/// aborts its `JoinHandle` on shutdown, exactly as the feeder is torn down.
pub async fn watch_prog(hub: TrafficHub, handle: BusHandle) {
    let mut ticker = tokio::time::interval(PROG_PROBE_INTERVAL);
    // Skip missed ticks rather than bursting to catch up after a slow probe.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        // Only probe while connected. When not connected, clear any stale set so
        // the UI stops highlighting a device we can no longer observe.
        if handle.status() != BusState::Connected {
            hub.set_prog_if_changed(BTreeSet::new());
            continue;
        }

        let source = ops::group_source(&handle);
        let lease = match handle.lease().await {
            Ok(lease) => lease,
            // The actor is gone; stop watching.
            Err(_) => break,
        };
        let channel = LeaseChannel::new(lease);
        match devices_in_programming_mode_within(channel, source, PROG_COLLECTION_WINDOW).await {
            Ok(found) => {
                let set: BTreeSet<IndividualAddress> = found.into_iter().collect();
                hub.set_prog_if_changed(set);
            }
            // A transient probe error (e.g. a momentary disconnect mid-window) is
            // not fatal: skip this tick and try again on the next one.
            Err(err) => {
                tracing::debug!("programming-mode probe failed: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use bussard_model::IndividualAddress;
    use bussard_model::codec::TypedValue;

    fn ia(s: &str) -> IndividualAddress {
        s.parse().expect("valid IA")
    }
    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("valid GA")
    }

    fn telegram(dest: &str, apci: ApciKind, value: Option<TypedValue>) -> DecodedTelegram {
        DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH,
            source: ia("1.1.30"),
            source_name: Some("Meteodata".to_string()),
            destination: DestinationRef::Group(ga(dest)),
            destination_name: Some("Windalarm".to_string()),
            apci,
            payload: vec![1],
            value,
            dpt: Some("1.005".parse().expect("dpt")),
            object_name: Some("obj".to_string()),
            decode_note: None,
        }
    }

    fn write(dest: &str) -> DecodedTelegram {
        telegram(
            dest,
            ApciKind::Write,
            Some(TypedValue::Bool {
                value: true,
                label: "Alarm",
            }),
        )
    }

    #[test]
    fn test_seq_is_monotonic_from_one() {
        let hub = TrafficHub::new();
        assert_eq!(hub.publish(&write("3/2/0")), 1);
        assert_eq!(hub.publish(&write("3/2/0")), 2);
        assert_eq!(hub.publish(&write("3/2/0")), 3);
        assert_eq!(hub.current_seq(), 3);
    }

    #[test]
    fn test_publish_stamps_seq_into_data() {
        let hub = TrafficHub::new();
        hub.publish(&write("3/2/0"));
        let (entries, max) = hub.backlog_since(0, 50);
        assert_eq!(max, 1);
        assert_eq!(entries[0]["seq"], 1);
        assert_eq!(entries[0]["destination"], "3/2/0");
    }

    #[test]
    fn test_backlog_evicts_oldest_beyond_cap() {
        let hub = TrafficHub::new();
        for _ in 0..(BACKLOG_CAP + 50) {
            hub.publish(&write("3/2/0"));
        }
        let (entries, max) = hub.backlog_since(0, BACKLOG_CAP + 100);
        assert_eq!(max, (BACKLOG_CAP + 50) as u64);
        // The backlog holds at most BACKLOG_CAP entries.
        assert_eq!(entries.len(), BACKLOG_CAP);
        // The oldest 50 were evicted, so the first retained seq is 51.
        assert_eq!(entries[0]["seq"], 51);
    }

    #[test]
    fn test_backlog_since_filters_by_last_event_id() {
        let hub = TrafficHub::new();
        for _ in 0..10 {
            hub.publish(&write("3/2/0"));
        }
        // Last-Event-ID = 7 => only seqs 8, 9, 10 replay.
        let (entries, max) = hub.backlog_since(7, 50);
        assert_eq!(max, 10);
        let seqs: Vec<u64> = entries
            .iter()
            .map(|e| e["seq"].as_u64().expect("seq"))
            .collect();
        assert_eq!(seqs, vec![8, 9, 10]);
    }

    #[test]
    fn test_backlog_since_limit_keeps_newest() {
        let hub = TrafficHub::new();
        for _ in 0..10 {
            hub.publish(&write("3/2/0"));
        }
        // limit 3 keeps the newest three of the 10.
        let (entries, _) = hub.backlog_since(0, 3);
        let seqs: Vec<u64> = entries
            .iter()
            .map(|e| e["seq"].as_u64().expect("seq"))
            .collect();
        assert_eq!(seqs, vec![8, 9, 10]);
    }

    #[test]
    fn test_replay_then_live_has_no_dup_or_gap() {
        // Simulate the SSE flow: subscribe, snapshot, then live events.
        let hub = TrafficHub::new();
        hub.publish(&write("3/2/0")); // seq 1
        hub.publish(&write("3/2/0")); // seq 2

        let mut rx = hub.subscribe();
        let (snapshot, max) = hub.backlog_since(0, 50);
        assert_eq!(max, 2);

        // Live events arrive after subscribe.
        hub.publish(&write("3/2/0")); // seq 3
        hub.publish(&write("3/2/0")); // seq 4

        let mut seen: Vec<u64> = snapshot
            .iter()
            .map(|e| e["seq"].as_u64().expect("seq"))
            .collect();
        // Drain the broadcast, skipping seq <= max (already in the snapshot).
        while let Ok(ev) = rx.try_recv() {
            if let HubEvent::Telegram { seq, .. } = ev {
                if seq > max {
                    seen.push(seq);
                }
            }
        }
        assert_eq!(seen, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ga_state_updated_by_write_and_response() {
        let hub = TrafficHub::new();
        hub.publish(&write("3/2/0"));
        let values = hub.state_values();
        assert_eq!(values["3/2/0"]["value"], "Alarm");
        assert_eq!(values["3/2/0"]["apci"], "write");
        assert_eq!(values["3/2/0"]["seq"], 1);
        assert_eq!(values["3/2/0"]["source"], "1.1.30");

        // A later Response updates the same GA.
        let resp = telegram(
            "3/2/0",
            ApciKind::Response,
            Some(TypedValue::Bool {
                value: false,
                label: "No alarm",
            }),
        );
        hub.publish(&resp);
        let values = hub.state_values();
        assert_eq!(values["3/2/0"]["value"], "No alarm");
        assert_eq!(values["3/2/0"]["apci"], "response");
    }

    /// Builds a programming-mode set from IA strings.
    fn prog_set(addrs: &[&str]) -> BTreeSet<IndividualAddress> {
        addrs.iter().map(|s| ia(s)).collect()
    }

    #[test]
    fn test_prog_values_empty_by_default() {
        // A fresh hub (watch never ran) reports an empty prog array, not absent.
        let hub = TrafficHub::new();
        assert_eq!(hub.prog_values(), json!([]));
    }

    #[test]
    fn test_set_prog_if_changed_reports_and_stores_change() {
        let hub = TrafficHub::new();
        // First non-empty set is a change; it is stored and reported.
        assert!(hub.set_prog_if_changed(prog_set(&["1.1.2"])));
        assert_eq!(hub.prog_values(), json!(["1.1.2"]));
    }

    #[test]
    fn test_set_prog_if_changed_is_noop_when_unchanged() {
        let hub = TrafficHub::new();
        assert!(hub.set_prog_if_changed(prog_set(&["1.1.2", "1.1.5"])));
        // The same set (order-independent, since it is a BTreeSet) is no change.
        assert!(!hub.set_prog_if_changed(prog_set(&["1.1.5", "1.1.2"])));
        // The stored value is unchanged and sorted (BTreeSet order).
        assert_eq!(hub.prog_values(), json!(["1.1.2", "1.1.5"]));
    }

    #[test]
    fn test_set_prog_if_changed_clear_to_empty_is_a_change() {
        let hub = TrafficHub::new();
        assert!(hub.set_prog_if_changed(prog_set(&["1.1.2"])));
        // Clearing a non-empty set back to empty is a genuine change.
        assert!(hub.set_prog_if_changed(BTreeSet::new()));
        assert_eq!(hub.prog_values(), json!([]));
        // Clearing an already-empty set is not.
        assert!(!hub.set_prog_if_changed(BTreeSet::new()));
    }

    #[test]
    fn test_set_prog_if_changed_publishes_prog_event() {
        // A change broadcasts a `prog` HubEvent carrying the new device list.
        let hub = TrafficHub::new();
        let mut rx = hub.subscribe();
        assert!(hub.set_prog_if_changed(prog_set(&["1.1.2", "1.1.7"])));

        let mut event = None;
        while let Ok(ev) = rx.try_recv() {
            if let HubEvent::Prog(v) = ev {
                event = Some(v);
                break;
            }
        }
        let v = event.expect("a prog event was published");
        assert_eq!(v, json!({ "devices": ["1.1.2", "1.1.7"] }));
    }

    #[test]
    fn test_set_prog_if_changed_noop_publishes_nothing() {
        // A no-op update must NOT broadcast a prog event.
        let hub = TrafficHub::new();
        assert!(hub.set_prog_if_changed(prog_set(&["1.1.2"])));
        let mut rx = hub.subscribe();
        assert!(!hub.set_prog_if_changed(prog_set(&["1.1.2"])));
        // Nothing new is queued for a fresh subscriber.
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn test_ga_state_ignores_reads() {
        let hub = TrafficHub::new();
        let mut read = write("3/2/0");
        read.apci = ApciKind::Read;
        read.value = None;
        read.payload = vec![];
        hub.publish(&read);
        // A read does not populate the state map.
        let values = hub.state_values();
        assert!(values.as_object().expect("object").is_empty());
    }

    /// The feeder emits a `bus` event on a genuine state CHANGE, driven by the
    /// bus watch (`state_changes`) rather than a polling tick. Pointing the bus
    /// at a dead gateway (`127.0.0.1:1`) forces a real Connecting -> Reconnecting
    /// transition, which must surface as exactly one `HubEvent::Bus`.
    #[tokio::test]
    async fn test_feed_emits_bus_event_on_state_change() -> Result<(), Box<dyn std::error::Error>> {
        use std::net::{Ipv4Addr, SocketAddrV4};

        use bussard_bus::Bus;
        use bussard_model::Model;
        use bussard_transport::ConnectionConfig;

        use crate::state::{BusStatus, ModelHandle};

        // An empty model directory loads fine (every file is optional).
        let tmp = tempfile::tempdir()?;
        let model = ModelHandle::new(Model::load(tmp.path())?);

        // A dead gateway on loopback: the actor tries once, fails, and moves
        // Connecting -> Reconnecting. ALWAYS 127.0.0.1 in tests.
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
        let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
        let status = BusStatus::connected(bussard_transport::TransportKind::Tunnel, handle.clone());

        let hub = TrafficHub::new();
        // Subscribe before spawning the feeder so no `bus` event is missed.
        let mut rx = hub.subscribe();

        tokio::spawn(feed(hub.clone(), handle.clone(), model, status));

        // Await the first bus event the feeder publishes on the state change.
        let evt = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Ok(HubEvent::Bus(v)) => return Some(v),
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
        })
        .await
        .map_err(|_| "timed out waiting for a bus event")?;

        let v = evt.ok_or("hub closed before a bus event")?;
        // A configured tunnel to a dead gateway reports a non-connected,
        // non-"disconnected" state (connecting/reconnecting).
        assert_eq!(v["transport"], "tunnel");
        assert_eq!(v["connected"], false);
        let state = v["state"].as_str().unwrap_or_default();
        assert!(
            matches!(state, "connecting" | "reconnecting"),
            "expected a retrying state, got {state:?}"
        );

        let _ = handle.close().await;
        Ok(())
    }
}
