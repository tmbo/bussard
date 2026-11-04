//! The relay API conformance cases (`services/enroll-relay/test/cases.json`,
//! shared with the hosted relay, #731) run against the in-process relay.
//!
//! The format is in `services/enroll-relay/README.md` ("API cases"). Each
//! case gets a fresh session id and fresh owner/other tokens; `short` cases
//! run against a relay whose sessions expire after `short.idle_seconds`
//! without a write and `short.max_seconds` at most.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bussard_viz::enroll_relay::EnrollRelay;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const CASES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/enroll-relay/test/cases.json"
);

/// A response as the cases check it.
struct Answer {
    status: u16,
    headers: HashMap<String, String>,
    body: Option<Value>,
    elapsed: Duration,
}

struct Context<'a> {
    fixtures: &'a Value,
    sid: String,
    owner: String,
    other: String,
}

fn random_b64<const N: usize>() -> Result<String, BoxError> {
    Ok(URL_SAFE_NO_PAD.encode(bussard_secure::enroll::random::<N>()?))
}

/// `value` with every `{"$envelope": name}` replaced by that fixture.
fn resolve(value: &Value, fixtures: &Value) -> Value {
    match value {
        Value::Object(map) => {
            if let (1, Some(Value::String(name))) = (map.len(), map.get("$envelope")) {
                return fixtures["envelopes"][name].clone();
            }
            Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), resolve(v, fixtures)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(|v| resolve(v, fixtures)).collect()),
        other => other.clone(),
    }
}

fn body_of(step: &Value, ctx: &Context<'_>) -> Result<Option<String>, BoxError> {
    let body = &step["body"];
    if body.is_null() {
        return Ok(None);
    }
    if let Some(json) = body.get("json") {
        return Ok(Some(json.to_string()));
    }
    if let Some(raw) = body.get("raw").and_then(Value::as_str) {
        return Ok(Some(raw.to_string()));
    }
    if let Some(name) = body.get("envelope").and_then(Value::as_str) {
        return Ok(Some(ctx.fixtures["envelopes"][name].to_string()));
    }
    if let Some(size) = body.get("envelope_bytes").and_then(Value::as_u64) {
        let mut template = ctx.fixtures["envelope_bytes_template"].clone();
        template["c"] = Value::String(String::new());
        let base = template.to_string().len();
        let fill = usize::try_from(size)? - base;
        template["c"] = Value::String("A".repeat(fill));
        let text = template.to_string();
        assert_eq!(text.len(), usize::try_from(size)?);
        return Ok(Some(text));
    }
    Err(format!("unknown body {body}").into())
}

async fn send(router: Router, request: Request<Body>) -> Result<Answer, BoxError> {
    let started = Instant::now();
    let response = router.oneshot(request).await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let bytes = response.into_body().collect().await?.to_bytes();
    let body = serde_json::from_slice(&bytes).ok();
    Ok(Answer {
        status,
        headers,
        body,
        elapsed: started.elapsed(),
    })
}

fn request(step: &Value, ctx: &Context<'_>) -> Result<Request<Body>, BoxError> {
    let method = step["method"].as_str().ok_or("method")?;
    let path = step["path"]
        .as_str()
        .ok_or("path")?
        .replace("{sid}", &ctx.sid);
    let mut builder = Request::builder().method(method).uri(path);
    match step["auth"].as_str() {
        Some("owner") => builder = builder.header("authorization", format!("Bearer {}", ctx.owner)),
        Some("other") => builder = builder.header("authorization", format!("Bearer {}", ctx.other)),
        Some(other) => return Err(format!("auth {other}").into()),
        None => {}
    }
    if let Some(origin) = step["origin"].as_str() {
        builder = builder.header("origin", origin);
    }
    if let Some(headers) = step["headers"].as_object() {
        for (k, v) in headers {
            builder = builder.header(k, v.as_str().ok_or("header value")?);
        }
    }
    Ok(match body_of(step, ctx)? {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body))?,
        None => builder.body(Body::empty())?,
    })
}

fn check(case: &str, expect: &Value, answer: &Answer, ctx: &Context<'_>) -> Result<(), BoxError> {
    let fail = |what: String| -> BoxError { format!("case {case:?}: {what}").into() };
    if let Some(status) = expect["status"].as_u64()
        && u64::from(answer.status) != status
    {
        return Err(fail(format!("status {} != {status}", answer.status)));
    }
    if let Some(json) = expect.get("json") {
        let want = resolve(json, ctx.fixtures);
        if answer.body.as_ref() != Some(&want) {
            return Err(fail(format!("body {:?} != {want}", answer.body)));
        }
    }
    if let Some(headers) = expect["headers"].as_object() {
        for (name, want) in headers {
            let got = answer.headers.get(&name.to_lowercase());
            match want.as_str() {
                Some(want) if got.map(String::as_str) != Some(want) => {
                    return Err(fail(format!("header {name} {got:?} != {want}")));
                }
                None if got.is_some() => {
                    return Err(fail(format!("header {name} present: {got:?}")));
                }
                _ => {}
            }
        }
    }
    let ms = answer.elapsed.as_millis();
    if let Some(min) = expect["min_ms"].as_u64()
        && ms < u128::from(min)
    {
        return Err(fail(format!("answered after {ms} ms < {min}")));
    }
    if let Some(max) = expect["max_ms"].as_u64()
        && ms > u128::from(max)
    {
        return Err(fail(format!("answered after {ms} ms > {max}")));
    }
    Ok(())
}

async fn run_case(case: &Value, router: Router, fixtures: &Value) -> Result<(), BoxError> {
    let name = case["name"].as_str().ok_or("name")?;
    let ctx = Context {
        fixtures,
        sid: random_b64::<16>()?,
        owner: random_b64::<32>()?,
        other: random_b64::<32>()?,
    };
    let mut pending = HashMap::new();
    for step in case["steps"].as_array().ok_or("steps")? {
        if let Some(ms) = step["sleep_ms"].as_u64() {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        } else if let Some(label) = step["await"].as_str() {
            let task: tokio::task::JoinHandle<Result<Answer, BoxError>> =
                pending.remove(label).ok_or("unknown await label")?;
            check(name, &step["expect"], &task.await??, &ctx)?;
        } else if let Some(label) = step["async"].as_str() {
            let request = request(step, &ctx)?;
            pending.insert(
                label.to_string(),
                tokio::spawn(send(router.clone(), request)),
            );
        } else {
            for _ in 0..step["repeat"].as_u64().unwrap_or(1) {
                let answer = send(router.clone(), request(step, &ctx)?).await?;
                check(name, &step["expect"], &answer, &ctx)?;
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_enroll_relay_conformance_cases() -> Result<(), BoxError> {
    let Ok(text) = std::fs::read_to_string(CASES) else {
        // The cases land with the hosted relay (#731, PR #735).
        eprintln!("skipped: {CASES} is not in this tree");
        return Ok(());
    };
    let cases: Value = serde_json::from_str(&text)?;
    assert_eq!(cases["format"].as_u64(), Some(2));
    let idle = Duration::from_secs(cases["short"]["idle_seconds"].as_u64().ok_or("idle")?);
    let max = Duration::from_secs(cases["short"]["max_seconds"].as_u64().ok_or("max")?);
    let default = EnrollRelay::new().router();
    let short = EnrollRelay::with_lifetimes(idle, max).router();
    let fixtures = &cases["fixtures"];
    let mut runs = Vec::new();
    for case in cases["cases"].as_array().ok_or("cases")? {
        let router = match case["relay"].as_str() {
            Some("short") => short.clone(),
            _ => default.clone(),
        };
        let case = case.clone();
        let fixtures = fixtures.clone();
        runs.push(tokio::spawn(async move {
            run_case(&case, router, &fixtures).await
        }));
    }
    let mut failures = Vec::new();
    for run in runs {
        if let Err(err) = run.await? {
            failures.push(err.to_string());
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
