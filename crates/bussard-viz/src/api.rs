//! The JSON API handlers: model, state, SSE traffic, and group-write.
//!
//! Handlers take the shared [`AppState`] and return either a JSON body or an
//! [`ApiError`] (mapped to the contract's status codes). The write path
//! replicates the CLI's `protected_refusal` + `resolve_dpt` gate so a protected
//! GA is never written without `force`, and encodes with the same
//! `parse_value` + `encode` + `bussard_bus::ops::write_group` stack.

use std::convert::Infallible;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use bussard_bus::ops::{self, WriteOptions};
use bussard_model::{Dpt, GroupAddress, Model, encode, parse_value};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use crate::error::ApiError;
use crate::state::AppState;
use crate::traffic::HubEvent;

/// The default number of backlog telegrams replayed to a fresh SSE subscriber.
const DEFAULT_BACKLOG: usize = 50;

/// `GET /api/model` — the precomputed model projection.
///
/// The model is immutable for the process lifetime, so this simply clones the
/// cached projection built at startup.
pub async fn get_model(State(state): State<AppState>) -> Json<Value> {
    Json(state.model_json.as_ref().clone())
}

/// `GET /api/state` — the bus status, current seq, and last value per GA.
pub async fn get_state(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "bus": state.bus.to_json(),
        "seq": state.hub.current_seq(),
        "values": state.hub.state_values(),
    }))
}

/// Query parameters for the SSE traffic endpoint.
#[derive(Debug, Deserialize)]
pub struct TrafficQuery {
    /// How many backlog telegrams to replay (default [`DEFAULT_BACKLOG`]).
    backlog: Option<usize>,
}

/// `GET /api/traffic` — the Server-Sent Events stream.
///
/// Emits `bus` (the current status, always first), then a replay of the backlog
/// as `telegram` events, then live `telegram`/`bus`/`gap` events. The replay
/// honors `Last-Event-ID` (or `?backlog=N`): it subscribes first, snapshots the
/// backlog, and drops any live event at or below the snapshot's max seq so the
/// stream has no duplicates and no gaps.
pub async fn get_traffic(
    State(state): State<AppState>,
    Query(query): Query<TrafficQuery>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // The replay floor: Last-Event-ID wins; else `?backlog=N` most-recent.
    let last_event_id: Option<u64> = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    // Subscribe BEFORE snapshotting so no telegram slips through the gap.
    let rx = state.hub.subscribe();

    let (replay, snapshot_max) = match last_event_id {
        Some(after) => state.hub.backlog_since(after, usize::MAX),
        None => {
            let limit = query.backlog.unwrap_or(DEFAULT_BACKLOG);
            state.hub.backlog_since(0, limit)
        }
    };

    // The opening `bus` event so the badge is correct immediately.
    let bus_event = to_sse(HubEvent::Bus(state.bus.to_json()));
    let bus_stream = tokio_stream::iter(std::iter::once(Ok(bus_event)));

    // The replay, as `telegram` events.
    let replay_stream = tokio_stream::iter(replay.into_iter().map(|data| {
        let seq = data.get("seq").and_then(Value::as_u64).unwrap_or(0);
        Ok(to_sse(HubEvent::Telegram { seq, data }))
    }));

    // The live tail: drop telegrams already covered by the snapshot; map a
    // broadcast lag into a `gap` event so the client re-snapshots.
    let live_stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(HubEvent::Telegram { seq, data }) => {
            if seq <= snapshot_max {
                None
            } else {
                Some(Ok(to_sse(HubEvent::Telegram { seq, data })))
            }
        }
        Ok(other) => Some(Ok(to_sse(other))),
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(count)) => {
            Some(Ok(to_sse(HubEvent::Gap { count })))
        }
    });

    let stream = bus_stream.chain(replay_stream).chain(live_stream);

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// Renders a [`HubEvent`] as an SSE [`Event`] with the right `event:`/`id:`.
fn to_sse(event: HubEvent) -> Event {
    match event {
        HubEvent::Telegram { seq, data } => Event::default()
            .event("telegram")
            .id(seq.to_string())
            .data(data.to_string()),
        HubEvent::Bus(status) => Event::default().event("bus").data(status.to_string()),
        HubEvent::Gap { count } => Event::default()
            .event("gap")
            .data(json!({ "count": count }).to_string()),
    }
}

/// The `POST /api/group-write` request body.
#[derive(Debug, Deserialize)]
pub struct GroupWrite {
    /// The target group address, e.g. `3/2/0`.
    address: String,
    /// The human value to encode, e.g. `on`, `75%`, `21.5`.
    value: String,
    /// Optional DPT override (wins over the GA's DPT from the model).
    dpt: Option<String>,
    /// Write even to a `protected` GA.
    #[serde(default)]
    force: bool,
}

/// `POST /api/group-write` — encode a value and send a `GroupValueWrite`.
///
/// Refuses a protected GA without `force` (403), errors when no DPT can be
/// resolved (422), errors on a bad address or un-encodable value (400), and
/// returns 503 when there is no bus. On success returns `200` with an echo of
/// what was written.
pub async fn post_group_write(
    State(state): State<AppState>,
    Json(req): Json<GroupWrite>,
) -> Result<Json<Value>, ApiError> {
    let ga: GroupAddress = req
        .address
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid group address {:?}", req.address)))?;

    let model = state.model.as_ref();

    // Resolve the DPT: --dpt wins, else the GA's DPT from groups.yaml.
    let dpt = resolve_dpt(req.dpt.as_deref(), model, ga)?;

    // Refuse a protected GA unless force.
    if let Some(reason) = protected_refusal(model, ga, req.force) {
        return Err(ApiError::Protected(reason));
    }

    // Parse and encode the value against the DPT.
    let typed = parse_value(&dpt, &req.value).map_err(|e| {
        ApiError::BadRequest(format!("parsing value {:?} for GA {ga}: {e}", req.value))
    })?;
    let payload = encode(&dpt, &typed).map_err(|e| {
        ApiError::BadRequest(format!("encoding {typed} as DPT {dpt} for GA {ga}: {e}"))
    })?;

    // Send it, if there is a bus.
    let handle = state.bus.handle().ok_or_else(|| {
        ApiError::BusUnavailable("bus not configured; running in model-only mode".to_string())
    })?;

    let outcome = ops::write_group(
        handle,
        ga,
        &payload,
        dpt.is_packable(),
        WriteOptions::default(),
    )
    .await
    .map_err(|e| ApiError::BusUnavailable(format!("could not write {ga}: {e}")))?;

    let ga_name = model.groups.groups.get(&ga).map(|g| g.name.clone());

    Ok(Json(json!({
        "ok": true,
        "address": ga.to_string(),
        "name": ga_name,
        "value": typed.to_string(),
        "dpt": dpt.to_string(),
        "confirmed": outcome.confirmed,
    })))
}

/// Returns a refusal message if `ga` is protected in the model and `force` is
/// not set; otherwise `None`. Replicated from the CLI write path.
fn protected_refusal(model: &Model, ga: GroupAddress, force: bool) -> Option<String> {
    if force {
        return None;
    }
    let group = model.groups.groups.get(&ga)?;
    if group.protected {
        Some(format!(
            "refusing to write to protected GA {ga} ({:?}); pass force to override",
            group.name
        ))
    } else {
        None
    }
}

/// Resolves the DPT to encode against: the `dpt` override wins, else the GA's
/// DPT from the model. Errors (as [`ApiError::NoDpt`] / [`ApiError::BadRequest`])
/// when neither is available or the override is malformed. Replicated from the
/// CLI write path.
fn resolve_dpt(
    dpt_override: Option<&str>,
    model: &Model,
    ga: GroupAddress,
) -> Result<Dpt, ApiError> {
    if let Some(s) = dpt_override {
        return s
            .parse()
            .map_err(|e| ApiError::BadRequest(format!("invalid dpt {s:?}: {e}")));
    }
    match model.groups.groups.get(&ga).and_then(|g| g.dpt) {
        Some(dpt) => Ok(dpt),
        None => Err(ApiError::NoDpt(format!(
            "GA {ga} has no DPT in groups.yaml; supply a dpt (e.g. 1.001)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("valid GA")
    }

    fn model_with(protected: bool, dpt: Option<&str>) -> Model {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/0/4"),
            Group {
                name: "Jalousie".to_string(),
                dpt: dpt.map(|d| d.parse().expect("dpt")),
                description: None,
                protected,
            },
        );
        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        }
    }

    #[test]
    fn test_protected_refused_without_force() {
        let m = model_with(true, Some("1.008"));
        let msg = protected_refusal(&m, ga("3/0/4"), false).expect("must refuse");
        assert!(msg.contains("protected"));
        assert!(msg.contains("Jalousie"));
    }

    #[test]
    fn test_protected_allowed_with_force() {
        let m = model_with(true, Some("1.008"));
        assert!(protected_refusal(&m, ga("3/0/4"), true).is_none());
    }

    #[test]
    fn test_unprotected_not_refused() {
        let m = model_with(false, Some("1.008"));
        assert!(protected_refusal(&m, ga("3/0/4"), false).is_none());
    }

    #[test]
    fn test_dpt_override_wins() {
        let m = model_with(false, Some("1.008"));
        let d = resolve_dpt(Some("5.001"), &m, ga("3/0/4")).expect("dpt");
        assert_eq!(d.to_string(), "5.001");
    }

    #[test]
    fn test_dpt_from_model() {
        let m = model_with(false, Some("1.008"));
        let d = resolve_dpt(None, &m, ga("3/0/4")).expect("dpt");
        assert_eq!(d.to_string(), "1.008");
    }

    #[test]
    fn test_dpt_missing_is_no_dpt_error() {
        let m = model_with(false, None);
        let err = resolve_dpt(None, &m, ga("3/0/4")).unwrap_err();
        assert!(matches!(err, ApiError::NoDpt(_)), "got {err:?}");
    }

    #[test]
    fn test_dpt_override_malformed_is_bad_request() {
        let m = model_with(false, Some("1.008"));
        let err = resolve_dpt(Some("not-a-dpt"), &m, ga("3/0/4")).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }
}
