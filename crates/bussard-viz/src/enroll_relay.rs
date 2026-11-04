//! An in-process enrolment relay (issue #729): the relay API of
//! `dev/enroll-protocol.md` on axum, for the tests and for local mode
//! (#732), where bussard serves the page and the relay on one origin.
//!
//! The relay is a mailbox: it stores envelopes it cannot read, keyed by
//! session id, and forgets a session 15 minutes after its last write (the
//! `PUT` or a `POST`), never later than 4 hours after its `PUT`. It holds
//! SHA-256 of the owner token, never the token. At most
//! [`MAX_WAITERS`] long polls wait per direction and session; another one
//! answers the oldest at once.
//!
//! | method and path | auth |
//! |---|---|
//! | `PUT /v1/sessions/{sid}` | owner (sets the token) |
//! | `POST /v1/sessions/{sid}/up` | none |
//! | `GET /v1/sessions/{sid}/up?after=&wait=` | owner |
//! | `POST /v1/sessions/{sid}/down` | owner |
//! | `GET /v1/sessions/{sid}/down?after=&wait=` | none |
//! | `DELETE /v1/sessions/{sid}` | owner |

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::put;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio::time::Instant;

/// How long a session lives after its last write.
pub const SESSION_IDLE: Duration = Duration::from_secs(15 * 60);
/// How long a session lives at most after its `PUT`.
pub const SESSION_MAX: Duration = Duration::from_secs(4 * 60 * 60);
/// Messages per direction and session.
pub const MAX_MESSAGES: usize = 500;
/// Long polls waiting at once per direction and session.
pub const MAX_WAITERS: usize = 4;
/// Bytes per envelope.
pub const MAX_ENVELOPE_BYTES: usize = 4096;
/// The longest long poll, in seconds.
pub const MAX_WAIT_SECS: u64 = 25;
/// Sessions the relay holds at once (a guard against a flood of `PUT`s).
pub const MAX_SESSIONS: usize = 64;

struct Session {
    token_hash: [u8; 32],
    /// The `PUT` plus the maximum lifetime.
    hard_expiry: Instant,
    expires: Instant,
    up: Vec<Value>,
    down: Vec<Value>,
    closed: bool,
    /// Bumped on every change, so long polls wake.
    changed: watch::Sender<u64>,
    /// The open long polls per direction, oldest first: an id and the flag
    /// that answers it early.
    waiters: [VecDeque<(u64, Arc<AtomicBool>)>; 2],
    next_waiter: u64,
}

impl Session {
    /// A write moves the expiry: the idle lifetime from now, capped.
    fn touch(&mut self, idle: Duration) {
        self.expires = (Instant::now() + idle).min(self.hard_expiry);
    }
}

/// An in-process relay: the session table and the session lifetimes.
#[derive(Clone)]
pub struct EnrollRelay {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    idle: Duration,
    max: Duration,
}

impl Default for EnrollRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EnrollRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollRelay")
            .field("idle", &self.idle)
            .field("max", &self.max)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Up,
    Down,
}

impl Dir {
    fn index(self) -> usize {
        match self {
            Dir::Up => 0,
            Dir::Down => 1,
        }
    }
}

impl EnrollRelay {
    /// An empty relay with the protocol's lifetimes: 15 minutes after the
    /// last write, at most 4 hours.
    #[must_use]
    pub fn new() -> Self {
        Self::with_lifetimes(SESSION_IDLE, SESSION_MAX)
    }

    /// An empty relay whose sessions live `idle` after their last write and
    /// at most `max` (the expiry tests; each can shorten the protocol's
    /// lifetime, never lengthen it).
    #[must_use]
    pub fn with_lifetimes(idle: Duration, max: Duration) -> Self {
        EnrollRelay {
            sessions: Arc::default(),
            idle: idle.min(SESSION_IDLE),
            max: max.min(SESSION_MAX),
        }
    }

    /// The relay's routes under `/v1/sessions`, to serve alone or merge into
    /// another router.
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/v1/sessions/{sid}",
                put(create_session).delete(delete_session),
            )
            .route(
                "/v1/sessions/{sid}/up",
                axum::routing::get(poll_up)
                    .post(post_up)
                    .options(preflight_up),
            )
            .route(
                "/v1/sessions/{sid}/down",
                axum::routing::get(poll_down)
                    .post(post_down)
                    .options(preflight_down),
            )
            .with_state(self.clone())
    }

    /// The session table, with expired sessions dropped. A poisoned lock
    /// (a panicked handler) still yields the table: it holds only mailboxes.
    fn sessions(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        let mut sessions = match self.sessions.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        sessions.retain(|_, s| now < s.expires);
        sessions
    }
}

/// A session id: 16 bytes as 22 base64url characters.
fn valid_sid(sid: &str) -> bool {
    sid.len() == 22 && is_base64url(sid)
}

fn is_base64url(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `{"v": 2, "pk", "n", "c"}` with non-empty base64url strings.
fn is_envelope(value: &Value) -> bool {
    value["v"] == json!(2)
        && ["pk", "n", "c"]
            .iter()
            .all(|k| value[*k].as_str().is_some_and(is_base64url))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let token = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    (!token.is_empty() && !token.contains(char::is_whitespace)).then_some(token)
}

/// SHA-256 of the bearer string's UTF-8 bytes.
fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Constant-time comparison of two token hashes.
fn same_hash(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_owner(session: &Session, headers: &HeaderMap) -> bool {
    bearer(headers).is_some_and(|token| same_hash(&token_hash(token), &session.token_hash))
}

fn json_response(code: StatusCode, value: &Value) -> Response {
    let mut response = (code, value.to_string()).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error(code: StatusCode, message: &str) -> Response {
    json_response(code, &json!({ "error": message }))
}

fn unknown() -> Response {
    error(StatusCode::NOT_FOUND, "unknown session")
}

fn unauthorized() -> Response {
    error(StatusCode::UNAUTHORIZED, "owner token required")
}

fn cors(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

fn preflight(methods: &'static str) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    for (name, value) in [
        (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        (header::ACCESS_CONTROL_ALLOW_METHODS, methods),
        (header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
        (header::ACCESS_CONTROL_MAX_AGE, "86400"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

async fn preflight_up() -> Response {
    preflight("POST")
}

async fn preflight_down() -> Response {
    preflight("GET")
}

async fn create_session(
    State(relay): State<EnrollRelay>,
    Path(sid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !valid_sid(&sid) {
        return error(StatusCode::BAD_REQUEST, "malformed session id");
    }
    let Some(token) = bearer(&headers) else {
        return unauthorized();
    };
    let mut sessions = relay.sessions();
    if sessions.contains_key(&sid) {
        return error(StatusCode::CONFLICT, "session exists");
    }
    if !serde_json::from_slice::<Value>(&body).is_ok_and(|v| v.is_object()) {
        return error(StatusCode::BAD_REQUEST, "body must be a JSON object");
    }
    if sessions.len() >= MAX_SESSIONS {
        return error(StatusCode::TOO_MANY_REQUESTS, "too many sessions");
    }
    let now = Instant::now();
    let hard_expiry = now + relay.max;
    sessions.insert(
        sid,
        Session {
            token_hash: token_hash(token),
            hard_expiry,
            expires: (now + relay.idle).min(hard_expiry),
            up: Vec::new(),
            down: Vec::new(),
            closed: false,
            changed: watch::Sender::new(0),
            waiters: [VecDeque::new(), VecDeque::new()],
            next_waiter: 0,
        },
    );
    json_response(StatusCode::CREATED, &json!({}))
}

async fn delete_session(
    State(relay): State<EnrollRelay>,
    Path(sid): Path<String>,
    headers: HeaderMap,
) -> Response {
    let mut sessions = relay.sessions();
    let Some(session) = sessions.get_mut(&sid) else {
        return unknown();
    };
    if !is_owner(session, &headers) {
        return unauthorized();
    }
    if !session.closed {
        session.closed = true;
        session.up.clear();
        session.down.clear();
        session.changed.send_modify(|v| *v += 1);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn post_up(
    State(relay): State<EnrollRelay>,
    Path(sid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    cors(post(&relay, &sid, &headers, Dir::Up, &body))
}

async fn post_down(
    State(relay): State<EnrollRelay>,
    Path(sid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    post(&relay, &sid, &headers, Dir::Down, &body)
}

async fn poll_up(
    State(relay): State<EnrollRelay>,
    Path(sid): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    poll(&relay, &sid, &headers, Dir::Up, query.as_deref()).await
}

async fn poll_down(
    State(relay): State<EnrollRelay>,
    Path(sid): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    cors(poll(&relay, &sid, &headers, Dir::Down, query.as_deref()).await)
}

/// Append an envelope. `down` is owner-only.
fn post(relay: &EnrollRelay, sid: &str, headers: &HeaderMap, dir: Dir, body: &[u8]) -> Response {
    let mut sessions = relay.sessions();
    let Some(session) = sessions.get_mut(sid).filter(|s| !s.closed) else {
        return unknown();
    };
    if dir == Dir::Down && !is_owner(session, headers) {
        return unauthorized();
    }
    if body.len() > MAX_ENVELOPE_BYTES {
        return error(StatusCode::TOO_MANY_REQUESTS, "envelope too large");
    }
    let envelope = match serde_json::from_slice::<Value>(body) {
        Ok(value) if is_envelope(&value) => value,
        _ => return error(StatusCode::BAD_REQUEST, "body must be an envelope"),
    };
    let mailbox = match dir {
        Dir::Up => &mut session.up,
        Dir::Down => &mut session.down,
    };
    if mailbox.len() >= MAX_MESSAGES {
        return error(StatusCode::TOO_MANY_REQUESTS, "message limit reached");
    }
    mailbox.push(envelope);
    let seq = mailbox.len();
    session.touch(relay.idle);
    session.changed.send_modify(|v| *v += 1);
    json_response(StatusCode::ACCEPTED, &json!({ "seq": seq }))
}

/// A query parameter, `None` when absent.
fn param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// `after`: up to 15 decimal digits.
fn parse_after(value: Option<&str>) -> Option<usize> {
    match value {
        None => Some(0),
        Some(v) if (1..=15).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit()) => {
            v.parse().ok()
        }
        Some(_) => None,
    }
}

/// `wait` in seconds, fractions to milliseconds allowed, cut to 25 seconds.
fn parse_wait(value: Option<&str>) -> Option<Duration> {
    let Some(value) = value else {
        return Some(Duration::ZERO);
    };
    let (whole, frac) = value.split_once('.').unwrap_or((value, ""));
    let digits = |s: &str, max: usize| s.len() <= max && s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty()
        || !digits(whole, 9)
        || !digits(frac, 3)
        || (value.contains('.') && frac.is_empty())
    {
        return None;
    }
    let secs: u64 = whole.parse().ok()?;
    let millis: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<3}").parse().ok()?
    };
    Some(
        (Duration::from_secs(secs) + Duration::from_millis(millis))
            .min(Duration::from_secs(MAX_WAIT_SECS)),
    )
}

/// The messages after `after`, waiting up to `wait` for one, the session's
/// delete or its expiry.
async fn poll(
    relay: &EnrollRelay,
    sid: &str,
    headers: &HeaderMap,
    dir: Dir,
    query: Option<&str>,
) -> Response {
    let (Some(after), Some(wait)) = (
        parse_after(param(query, "after")),
        parse_wait(param(query, "wait")),
    ) else {
        // The 404 and 401 checks come first.
        return match relay.sessions().get(sid) {
            None => unknown(),
            Some(session) if dir == Dir::Up && !is_owner(session, headers) => unauthorized(),
            Some(_) => error(
                StatusCode::BAD_REQUEST,
                "after and wait must be non-negative numbers",
            ),
        };
    };
    let (mut changed, waiter) = {
        let mut sessions = relay.sessions();
        let Some(session) = sessions.get_mut(sid) else {
            return unknown();
        };
        if dir == Dir::Up && !is_owner(session, headers) {
            return unauthorized();
        }
        let waiter = if wait.is_zero() {
            None
        } else {
            Some(Waiter::register(relay, sid, dir, session))
        };
        (session.changed.subscribe(), waiter)
    };
    let deadline = Instant::now() + wait;
    loop {
        // Mark the current version seen before reading, so a change between
        // the read and the wait still wakes us.
        changed.borrow_and_update();
        let (messages, closed, expires) = {
            let sessions = relay.sessions();
            let Some(session) = sessions.get(sid) else {
                return unknown();
            };
            let mailbox = match dir {
                Dir::Up => &session.up,
                Dir::Down => &session.down,
            };
            let messages: Vec<Value> = mailbox
                .iter()
                .enumerate()
                .skip(after)
                .map(|(i, body)| json!({ "seq": i + 1, "body": body }))
                .collect();
            (messages, session.closed, session.expires)
        };
        let now = Instant::now();
        let evicted = waiter.as_ref().is_some_and(Waiter::evicted);
        if closed || !messages.is_empty() || now >= deadline || evicted {
            let messages = if closed { Vec::new() } else { messages };
            return json_response(
                StatusCode::OK,
                &json!({ "messages": messages, "closed": closed }),
            );
        }
        // Wake at the deadline, or at expiry to answer 404.
        let wake = deadline.min(expires);
        let _ = tokio::time::timeout_at(wake, changed.changed()).await;
    }
}

/// One open long poll, registered with its session. A newer poll beyond
/// [`MAX_WAITERS`] sets `evicted` and wakes it; dropping it deregisters.
struct Waiter {
    relay: EnrollRelay,
    sid: String,
    dir: Dir,
    id: u64,
    evicted: Arc<AtomicBool>,
}

impl Waiter {
    fn register(relay: &EnrollRelay, sid: &str, dir: Dir, session: &mut Session) -> Self {
        let id = session.next_waiter;
        session.next_waiter += 1;
        let evicted = Arc::new(AtomicBool::new(false));
        let queue = &mut session.waiters[dir.index()];
        queue.push_back((id, Arc::clone(&evicted)));
        if queue.len() > MAX_WAITERS
            && let Some((_, oldest)) = queue.pop_front()
        {
            oldest.store(true, Ordering::SeqCst);
            session.changed.send_modify(|v| *v += 1);
        }
        Waiter {
            relay: relay.clone(),
            sid: sid.to_string(),
            dir,
            id,
            evicted,
        }
    }

    fn evicted(&self) -> bool {
        self.evicted.load(Ordering::SeqCst)
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let mut sessions = self.relay.sessions();
        if let Some(session) = sessions.get_mut(&self.sid) {
            session.waiters[self.dir.index()].retain(|(id, _)| *id != self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    type BoxError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), BoxError>;

    const SID: &str = "/v1/sessions/AAAAAAAAAAAAAAAAAAAAAA";
    const ENVELOPE: &str = r#"{"v":2,"pk":"AA","n":"AA","c":"AA"}"#;

    async fn call(
        router: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: &str,
    ) -> Result<(StatusCode, Value), BoxError> {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::from(body.to_string()))?)
            .await?;
        let code = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok((code, value))
    }

    #[tokio::test]
    async fn test_router_mailbox_round_trip() -> TestResult {
        let router = EnrollRelay::new().router();
        assert_eq!(
            call(&router, "PUT", SID, Some("t"), "{}").await?.0,
            StatusCode::CREATED
        );
        let up = format!("{SID}/up");
        let (code, body) = call(&router, "POST", &up, None, ENVELOPE).await?;
        assert_eq!(
            (code, body["seq"].as_u64()),
            (StatusCode::ACCEPTED, Some(1))
        );
        assert_eq!(
            call(&router, "GET", &up, Some("x"), "").await?.0,
            StatusCode::UNAUTHORIZED
        );
        let (_, body) = call(&router, "GET", &format!("{up}?after=0"), Some("t"), "").await?;
        assert_eq!(body["messages"][0]["body"]["pk"], json!("AA"));
        let (_, body) = call(&router, "GET", &format!("{up}?after=1"), Some("t"), "").await?;
        assert_eq!(body, json!({ "messages": [], "closed": false }));
        assert_eq!(
            call(&router, "DELETE", SID, Some("t"), "").await?.0,
            StatusCode::NO_CONTENT
        );
        let (_, body) = call(&router, "GET", &format!("{SID}/down"), None, "").await?;
        assert_eq!(body, json!({ "messages": [], "closed": true }));
        Ok(())
    }

    #[tokio::test]
    async fn test_poll_wakes_on_post() -> TestResult {
        let router = EnrollRelay::new().router();
        call(&router, "PUT", SID, Some("t"), "{}").await?;
        let poller = {
            let router = router.clone();
            tokio::spawn(async move {
                let uri = format!("{SID}/up?after=0&wait=20");
                call(&router, "GET", &uri, Some("t"), "").await
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        call(&router, "POST", &format!("{SID}/up"), None, ENVELOPE).await?;
        let (code, body) = poller.await??;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["messages"].as_array().map(Vec::len), Some(1));
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn test_parse_wait_clamps_and_rejects() {
        assert_eq!(parse_wait(None), Some(Duration::ZERO));
        assert_eq!(parse_wait(Some("1.5")), Some(Duration::from_millis(1500)));
        assert_eq!(parse_wait(Some("99")), Some(Duration::from_secs(25)));
        for bad in ["-1", "soon", "", "1.", ".5", "1.2345"] {
            assert_eq!(parse_wait(Some(bad)), None, "{bad}");
        }
        assert_eq!(parse_after(Some("x")), None);
        assert_eq!(parse_after(Some("3")), Some(3));
    }
}
