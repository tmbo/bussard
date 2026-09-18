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
use bussard_model::{ApduSize, Dpt, GroupAddress, Model, encode, parse_value};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use crate::error::ApiError;
use crate::state::{AppState, ModelSnapshot};
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
/// Refuses a protected GA without `force` (403), errors when no DPT can be
/// resolved for a `value` write (422), errors on a bad address / un-encodable
/// value / bad hex / DPT-size mismatch (400), and returns 503 when there is no
/// bus. On success returns `200` with an echo of what was written.
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
    let ga: GroupAddress = req
        .address
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid group address {:?}", req.address)))?;

    // Read the CURRENT model snapshot so a reload's protected-GA changes and
    // DPT edits are enforced immediately on the very next write.
    let snapshot = state.model.current();
    let model = snapshot.model.as_ref();

    // Exactly one of value / payload.
    match (&req.value, &req.payload) {
        (Some(value), None) => write_value(&state, ga, model, value, &req).await,
        (None, Some(payload_hex)) => write_payload(&state, ga, model, payload_hex, &req).await,
        (Some(_), Some(_)) => Err(ApiError::BadRequest(
            "provide exactly one of value or payload, not both".to_string(),
        )),
        (None, None) => Err(ApiError::BadRequest(
            "provide exactly one of value or payload".to_string(),
        )),
    }
}

/// `POST /api/reload` — reload the model from disk and swap it atomically.
///
/// Re-runs `Model::load` on the server's model directory. On success it builds a
/// fresh [`ModelSnapshot`] (with the next `model_version`), swaps it into the
/// shared [`ModelHandle`](crate::state::ModelHandle) in one move, emits a `model`
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

    // Build the next snapshot at version = current + 1, then swap it in. The
    // read + increment is not a CAS, but reloads are user-initiated and rare
    // (one clicked button); a monotonic bump is all the contract requires.
    let next_version = state.model.current().version + 1;
    let snapshot = ModelSnapshot::new(model, next_version);
    let stats = snapshot.json.get("stats").cloned().unwrap_or(Value::Null);
    state.model.swap(std::sync::Arc::new(snapshot));

    // Tell connected pages to refetch /api/model.
    let event = json!({ "model_version": next_version, "stats": stats });
    state.hub.publish_model(event.clone());

    Ok(Json(json!({
        "ok": true,
        "model_version": next_version,
        "stats": stats,
    })))
}

/// The `value` write path: resolve a DPT, encode the human value, send it.
async fn write_value(
    state: &AppState,
    ga: GroupAddress,
    model: &Model,
    value: &str,
    req: &GroupWrite,
) -> Result<Json<Value>, ApiError> {
    // Resolve the DPT: --dpt wins, else the GA's DPT from groups.yaml.
    let dpt = resolve_dpt(req.dpt.as_deref(), model, ga)?;

    // Refuse a protected GA unless force.
    if let Some(reason) = protected_refusal(model, ga, req.force) {
        return Err(ApiError::Protected(reason));
    }

    // Parse and encode the value against the DPT.
    let typed = parse_value(&dpt, value)
        .map_err(|e| ApiError::BadRequest(format!("parsing value {value:?} for GA {ga}: {e}")))?;
    let payload = encode(&dpt, &typed).map_err(|e| {
        ApiError::BadRequest(format!("encoding {typed} as DPT {dpt} for GA {ga}: {e}"))
    })?;

    let outcome = send_write(state, ga, &payload, dpt.is_packable()).await?;
    let ga_name = model.groups.groups.get(&ga).map(|g| g.name.clone());

    Ok(Json(json!({
        "ok": true,
        "address": ga.to_string(),
        "name": ga_name,
        "value": typed.to_string(),
        "payload": hex_encode(&payload),
        "dpt": dpt.to_string(),
        "confirmed": outcome.confirmed,
    })))
}

/// The raw `payload` write path: decode hex, validate against a known DPT size,
/// send verbatim.
///
/// Unlike the `value` path, a missing DPT is NOT an error here: raw bytes can be
/// sent with no DPT at all (sent unpacked). When a DPT IS known, the byte length
/// is validated and a packable DPT's single byte is sent packed.
async fn write_payload(
    state: &AppState,
    ga: GroupAddress,
    model: &Model,
    payload_hex: &str,
    req: &GroupWrite,
) -> Result<Json<Value>, ApiError> {
    // Refuse a protected GA unless force (identically to the value path).
    if let Some(reason) = protected_refusal(model, ga, req.force) {
        return Err(ApiError::Protected(reason));
    }

    let payload = decode_hex(payload_hex)
        .map_err(|e| ApiError::BadRequest(format!("invalid payload hex {payload_hex:?}: {e}")))?;
    if payload.is_empty() {
        return Err(ApiError::BadRequest(
            "payload must decode to at least one byte".to_string(),
        ));
    }

    // A DPT may or may not be known for a raw write: the `dpt` override wins,
    // else the GA's DPT from the model, else none.
    let dpt = optional_dpt(req.dpt.as_deref(), model, ga)?;

    // Decide packing and validate the byte length against a known DPT size.
    let packed = match dpt {
        Some(d) => {
            validate_payload_size(d, &payload, ga)?;
            d.is_packable()
        }
        // No DPT anywhere: safe default is unpacked (full octet). See the
        // endpoint docs.
        None => false,
    };

    let outcome = send_write(state, ga, &payload, packed).await?;
    let ga_name = model.groups.groups.get(&ga).map(|g| g.name.clone());

    Ok(Json(json!({
        "ok": true,
        "address": ga.to_string(),
        "name": ga_name,
        "value": Value::Null,
        "payload": hex_encode(&payload),
        "dpt": dpt.map(|d| d.to_string()),
        "confirmed": outcome.confirmed,
    })))
}

/// Sends the payload on the bus, mapping the absent-bus case to 503.
async fn send_write(
    state: &AppState,
    ga: GroupAddress,
    payload: &[u8],
    packed: bool,
) -> Result<ops::WriteOutcome, ApiError> {
    let handle = state.bus.handle().ok_or_else(|| {
        ApiError::BusUnavailable("bus not configured; running in model-only mode".to_string())
    })?;

    ops::write_group(handle, ga, payload, packed, WriteOptions::default())
        .await
        .map_err(|e| ApiError::BusUnavailable(format!("could not write {ga}: {e}")))
}

/// Validates a raw payload's byte length against a known DPT's expected size.
///
/// A packable DPT ([`ApduSize::Bits`]) expects exactly one byte holding a value
/// that fits in the 6-bit APDU (`<= 0x3F`); a byte-sized DPT expects exactly that
/// many whole octets. A DPT whose size bussard does not model is not validated.
fn validate_payload_size(dpt: Dpt, payload: &[u8], ga: GroupAddress) -> Result<(), ApiError> {
    match dpt.expected_size() {
        Some(ApduSize::Bits(_)) => {
            if payload.len() != 1 {
                return Err(ApiError::BadRequest(format!(
                    "payload for GA {ga} DPT {dpt} must be 1 byte (sub-byte / packable), got {}",
                    payload.len()
                )));
            }
            // The value must fit in the low 6 bits, or packing would truncate it.
            if payload[0] > 0x3f {
                return Err(ApiError::BadRequest(format!(
                    "payload byte {:#04x} for GA {ga} DPT {dpt} exceeds the 6-bit packable range (max 0x3f)",
                    payload[0]
                )));
            }
            Ok(())
        }
        Some(ApduSize::Bytes(n)) => {
            if payload.len() != usize::from(n) {
                return Err(ApiError::BadRequest(format!(
                    "payload for GA {ga} DPT {dpt} must be {n} byte(s), got {}",
                    payload.len()
                )));
            }
            Ok(())
        }
        // Size not modelled: allow any length (mirrors is_packable's None case).
        None => Ok(()),
    }
}

/// Decodes an even-length hex string (upper- or lowercase) into bytes.
///
/// Returns a human-readable error message for an odd length or a non-hex digit.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!(
            "odd length ({} chars); hex must be byte-aligned",
            s.len()
        ));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decodes a single ASCII hex digit into its 0..=15 value.
fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("non-hex character {:?}", other as char)),
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

/// Resolves an optional DPT for a raw write: the `dpt` override wins (a malformed
/// override is a 400), else the GA's DPT from the model, else `None`.
///
/// Unlike [`resolve_dpt`], a missing DPT is not an error: raw payloads may be
/// sent unmodelled.
fn optional_dpt(
    dpt_override: Option<&str>,
    model: &Model,
    ga: GroupAddress,
) -> Result<Option<Dpt>, ApiError> {
    if let Some(s) = dpt_override {
        return s
            .parse()
            .map(Some)
            .map_err(|e| ApiError::BadRequest(format!("invalid dpt {s:?}: {e}")));
    }
    Ok(model.groups.groups.get(&ga).and_then(|g| g.dpt))
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

    // --- hex helpers ---------------------------------------------------------

    #[test]
    fn test_decode_hex_roundtrip_and_case() {
        assert_eq!(decode_hex("0b64").expect("hex"), vec![0x0b, 0x64]);
        assert_eq!(decode_hex("0B64").expect("hex"), vec![0x0b, 0x64]);
        assert_eq!(decode_hex("").expect("hex"), Vec::<u8>::new());
        assert_eq!(hex_encode(&[0x0b, 0x64]), "0b64");
    }

    #[test]
    fn test_decode_hex_odd_length_errors() {
        let err = decode_hex("abc").unwrap_err();
        assert!(err.contains("odd length"), "got {err}");
    }

    #[test]
    fn test_decode_hex_bad_char_errors() {
        let err = decode_hex("zz").unwrap_err();
        assert!(err.contains("non-hex"), "got {err}");
    }

    // --- optional_dpt --------------------------------------------------------

    #[test]
    fn test_optional_dpt_none_when_unmodelled() {
        let m = model_with(false, None);
        let d = optional_dpt(None, &m, ga("3/0/4")).expect("ok");
        assert!(d.is_none(), "got {d:?}");
    }

    #[test]
    fn test_optional_dpt_override_malformed_is_bad_request() {
        let m = model_with(false, None);
        let err = optional_dpt(Some("nope"), &m, ga("3/0/4")).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    // --- validate_payload_size -----------------------------------------------

    fn dpt(s: &str) -> Dpt {
        s.parse().expect("dpt")
    }

    #[test]
    fn test_validate_payload_size_packable_one_byte_ok() {
        // 1.x is 1-bit / packable: a single byte <= 0x3f is fine.
        validate_payload_size(dpt("1.001"), &[0x01], ga("3/0/4")).expect("ok");
    }

    #[test]
    fn test_validate_payload_size_packable_wrong_length() {
        let err = validate_payload_size(dpt("1.001"), &[0x00, 0x01], ga("3/0/4")).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn test_validate_payload_size_packable_over_6_bits() {
        // A 1-byte payload > 0x3f cannot be packed into the 6-bit APDU.
        let err = validate_payload_size(dpt("3.007"), &[0x40], ga("3/0/4")).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn test_validate_payload_size_bytes_ok_and_mismatch() {
        // 9.x is a 2-byte float.
        validate_payload_size(dpt("9.001"), &[0x0c, 0x1a], ga("3/0/4")).expect("ok");
        let err = validate_payload_size(dpt("9.001"), &[0x0c], ga("3/0/4")).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn test_validate_payload_size_unmodelled_allows_any() {
        // Main 99 has no modelled size: any length passes.
        validate_payload_size(dpt("99"), &[0x01, 0x02, 0x03], ga("3/0/4")).expect("ok");
    }
}
