//! The JSON API handlers: model, state, SSE traffic, and group-write.
//!
//! Handlers take the shared [`AppState`] and return either a JSON body or an
//! [`ApiError`] (mapped to the contract's status codes). The write path is the
//! shared checked write in [`bussard_service::write`] (issue #86), the same one
//! `bussard write` and the MCP server use: a protected GA is never written
//! without `force`. This module only maps its [`WriteRefusal`] to HTTP.

use std::convert::Infallible;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use bussard_model::{GroupAddress, Model};
use bussard_service::{
    DptOverridePolicy, WriteCheck, WriteRefusal, WriteValue, prepare_group_write,
};
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
/// Clones the current snapshot's cached projection. `POST /api/reload` can swap
/// the snapshot underneath, so this reads through the [`ModelHandle`] every call
/// rather than capturing an `Arc` once.
pub async fn get_model(State(state): State<AppState>) -> Json<Value> {
    Json(state.model.current().json.as_ref().clone())
}

/// `GET /api/state` — the bus status, current seq, last value per GA, and the
/// individual addresses currently observed in programming mode.
///
/// `prog` is an array of IA strings; it is empty when none are in programming
/// mode or when `--watch-prog` is off (the watch never runs, so the set stays
/// empty). See the `prog` SSE event for live updates.
pub async fn get_state(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "bus": state.bus.to_json(),
        "seq": state.hub.current_seq(),
        "values": state.hub.state_values(),
        "prog": state.hub.prog_values(),
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
    // broadcast lag into a `gap` event so the client re-snapshots. The stream
    // ENDS on `Shutdown` (take_while) so an open SSE connection cannot hold
    // axum's graceful shutdown open forever.
    let live_stream = BroadcastStream::new(rx)
        .take_while(|item| !matches!(item, Ok(HubEvent::Shutdown)))
        .filter_map(move |item| match item {
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
        HubEvent::Model(data) => Event::default().event("model").data(data.to_string()),
        HubEvent::Prog(data) => Event::default().event("prog").data(data.to_string()),
        HubEvent::Gap { count } => Event::default()
            .event("gap")
            .data(json!({ "count": count }).to_string()),
        // Filtered out by take_while before mapping; never rendered.
        HubEvent::Shutdown => Event::default().event("shutdown"),
    }
}

/// The `POST /api/group-write` request body.
///
/// Exactly one of [`value`](GroupWrite::value) or [`payload`](GroupWrite::payload)
/// must be present: `value` takes the human-value + `parse_value` encode path;
/// `payload` takes raw hex bytes sent verbatim (validated against the DPT size
/// when one is known).
#[derive(Debug, Deserialize)]
pub struct GroupWrite {
    /// The target group address, e.g. `3/2/0`.
    address: String,
    /// The human value to encode, e.g. `on`, `75%`, `21.5`. Mutually exclusive
    /// with [`payload`](GroupWrite::payload).
    value: Option<String>,
    /// Raw payload bytes as hex (e.g. `"0b64"`), sent verbatim. Mutually
    /// exclusive with [`value`](GroupWrite::value).
    payload: Option<String>,
    /// Optional DPT override (wins over the GA's DPT from the model).
    dpt: Option<String>,
    /// Write even to a `protected` GA.
    #[serde(default)]
    force: bool,
}

/// `POST /api/group-write` — send a `GroupValueWrite`.
///
/// Accepts either a human `value` (encoded through `parse_value` + `encode`) or
/// raw hex `payload` bytes (sent verbatim); exactly one must be present.
///
/// Refuses every write with `403 writes_disabled` when the server was started
/// without `--allow-writes`, refuses a protected GA without `force` (403),
/// errors when no DPT can be resolved for a `value` write (422), errors on a
/// bad address / un-encodable value / bad hex / DPT-size mismatch (400), and
/// returns 503 when there is no bus. On success returns `200` with an echo of
/// what was written.
///
/// ## Raw payload packing
///
/// When a DPT is known (from the model or the `dpt` param), the decoded byte
/// length is validated against [`Dpt::expected_size`]: a sub-byte (packable)
/// DPT expects exactly one byte with value `<= 0x3F`, and a byte-sized DPT
/// expects that many whole octets. A 1-byte payload for a packable DPT is sent
/// packed into the 6-bit APDU, exactly as the `value` path would.
///
/// When NO DPT is known anywhere, the raw write is still allowed but sent
/// **unpacked** (as a full data octet): a lone 1-byte payload `<= 0x3F` is
/// ambiguous between the packed 1-bit form and a byte-sized value, and the
/// unpacked full octet is the form every device reads correctly (issue #59).
pub async fn post_group_write(
    State(state): State<AppState>,
    Json(req): Json<GroupWrite>,
) -> Result<Json<Value>, ApiError> {
    // Writes are opt-in. A bare `bussard viz` is a viewer: the endpoint exists
    // (so the UI can explain itself) but never reaches the bus.
    if !state.security.allow_writes {
        return Err(ApiError::WritesDisabled(
            "this viz server is read-only; restart it with `bussard viz --allow-writes` \
             to enable group writes"
                .to_string(),
        ));
    }

    let ga: GroupAddress = req
        .address
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid group address {:?}", req.address)))?;

    // Read the CURRENT model snapshot so a reload's protected-GA changes and
    // DPT edits are enforced immediately on the very next write.
    let snapshot = state.model.current();
    let model = snapshot.model.as_ref();

    // Exactly one of value / payload.
    let value = match (&req.value, &req.payload) {
        (Some(value), None) => WriteValue::Human(value),
        (None, Some(payload_hex)) => WriteValue::Hex(payload_hex),
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "provide exactly one of value or payload, not both".to_string(),
            ));
        }
        (None, None) => {
            return Err(ApiError::BadRequest(
                "provide exactly one of value or payload".to_string(),
            ));
        }
    };

    // Every check short of sending: protected (unless force), the DPT (the
    // `dpt` override wins, else groups.yaml), then encode or validate the raw
    // payload's size.
    let check = WriteCheck {
        dpt: req.dpt.as_deref(),
        dpt_policy: DptOverridePolicy::Trust,
        force: req.force,
    };
    let write =
        prepare_group_write(Some(model), ga, value, &check).map_err(|r| api_refusal(ga, r))?;

    let service = state.bus.service().ok_or_else(|| {
        ApiError::BusUnavailable("bus not configured; running in model-only mode".to_string())
    })?;
    let sent = service
        .send_prepared(write)
        .await
        .map_err(|r| api_refusal(ga, r))?;

    Ok(Json(json!({
        "ok": true,
        "address": ga.to_string(),
        "name": sent.write.name,
        "value": sent.write.value,
        "payload": hex_encode(&sent.write.payload),
        "dpt": sent.write.dpt.map(|d| d.to_string()),
        "confirmed": sent.confirmed,
    })))
}

/// `POST /api/reload` — reload the model from disk and swap it atomically.
///
/// Re-runs `Model::load` on the server's model directory. On success it installs
/// the model into the shared [`ModelHandle`](crate::state::ModelHandle) as the
/// next `model_version` in one move, emits a `model`
/// SSE event so connected pages refetch `/api/model`, and returns `200` with the
/// new `{model_version, stats}`.
///
/// Load-failure semantics are the whole point of issue #65: a broken model must
/// NEVER replace a good one. On a [`LoadError`](bussard_model::LoadError) it
/// returns `422` with `{"error":{"code":"model_invalid","message":<display>}}`
/// and keeps serving the previous model unchanged (no swap, no SSE event).
pub async fn post_reload(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    // Re-read the model directory. A failure leaves the current snapshot intact.
    let model = Model::load(&state.dir)
        .map_err(|e| ApiError::ModelInvalid(format!("model reload failed: {e}")))?;

    // Install it as the next version (current + 1).
    let snapshot = state.model.install(model);
    let next_version = snapshot.version;
    let stats = snapshot.json.get("stats").cloned().unwrap_or(Value::Null);

    // Tell connected pages to refetch /api/model.
    let event = json!({ "model_version": next_version, "stats": stats });
    state.hub.publish_model(event.clone());

    Ok(Json(json!({
        "ok": true,
        "model_version": next_version,
        "stats": stats,
    })))
}

/// Maps a [`WriteRefusal`] to the `/api/group-write` contract: `403` for a
/// protected GA without `force`, `422` when no DPT resolves, `503` when the bus
/// cannot take the write, `400` for anything wrong with the request.
fn api_refusal(ga: GroupAddress, refusal: WriteRefusal) -> ApiError {
    match refusal {
        WriteRefusal::Protected { name, .. } => ApiError::Protected(format!(
            "refusing to write to protected GA {ga} ({name:?}); pass force to override"
        )),
        WriteRefusal::NoDpt { .. } => ApiError::NoDpt(format!(
            "GA {ga} has no DPT in groups.yaml; supply a dpt (e.g. 1.001)"
        )),
        WriteRefusal::WritesDisabled => ApiError::WritesDisabled(
            "this viz server's bus is read-only; restart it with `bussard viz --allow-writes` \
             to enable group writes"
                .to_string(),
        ),
        WriteRefusal::Bus(err) => ApiError::BusUnavailable(format!("could not write {ga}: {err}")),
        // Invalid dpt / value / encode / hex / empty / size: the request is bad.
        other => ApiError::BadRequest(other.to_string()),
    }
}

/// Encodes bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn model_with(protected: bool, dpt: Option<&str>) -> Result<Model, Box<dyn std::error::Error>> {
        let mut groups = BTreeMap::new();
        groups.insert(
            "3/0/4".parse()?,
            Group {
                name: "Living Room Blind".to_string(),
                dpt: dpt.map(str::parse).transpose()?,
                description: None,
                protected,
                secure: false,
            },
        );
        Ok(Model {
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
        })
    }

    /// The API error a write to `3/0/4` is refused with.
    fn refused(
        model: &Model,
        value: WriteValue<'_>,
        dpt: Option<&str>,
    ) -> Result<ApiError, Box<dyn std::error::Error>> {
        let ga: GroupAddress = "3/0/4".parse()?;
        let check = WriteCheck {
            dpt,
            dpt_policy: DptOverridePolicy::Trust,
            force: false,
        };
        match prepare_group_write(Some(model), ga, value, &check) {
            Ok(write) => Err(format!("expected a refusal, got {write:?}").into()),
            Err(refusal) => Ok(api_refusal(ga, refusal)),
        }
    }

    #[test]
    fn test_api_refusal_protected_is_403_with_force_hint() -> TestResult {
        let m = model_with(true, Some("1.008"))?;
        let err = refused(&m, WriteValue::Human("down"), None)?;
        assert!(
            matches!(&err, ApiError::Protected(msg)
            if msg.contains("Living Room Blind") && msg.contains("pass force")),
            "{err:?}"
        );
        // A raw payload is refused identically.
        let err = refused(&m, WriteValue::Hex("01"), None)?;
        assert!(matches!(err, ApiError::Protected(_)), "{err:?}");
        Ok(())
    }

    #[test]
    fn test_api_refusal_missing_dpt_is_no_dpt() -> TestResult {
        let m = model_with(false, None)?;
        let err = refused(&m, WriteValue::Human("on"), None)?;
        assert!(matches!(err, ApiError::NoDpt(_)), "{err:?}");
        Ok(())
    }

    #[test]
    fn test_api_refusal_bad_request_shapes() -> TestResult {
        let m = model_with(false, Some("1.008"))?;
        for (value, dpt) in [
            (WriteValue::Human("on"), Some("not-a-dpt")),
            (WriteValue::Human("sideways"), None),
            (WriteValue::Hex("0"), None),
            (WriteValue::Hex(""), None),
            (WriteValue::Hex("0101"), None),
        ] {
            let err = refused(&m, value, dpt)?;
            assert!(matches!(err, ApiError::BadRequest(_)), "{value:?}: {err:?}");
        }
        Ok(())
    }

    #[test]
    fn test_hex_encode_lowercase() {
        assert_eq!(hex_encode(&[0x0a, 0xff]), "0aff");
    }
}
