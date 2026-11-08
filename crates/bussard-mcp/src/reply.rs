//! The reply helpers every tool shares (issue #905): a structured result, a
//! refusal the assistant reads out, a bad-argument error, and merging
//! result fields.

use bussard_model::Model;
use bussard_service::report::{Refusal, Report};
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use serde_json::{Value, json};

/// A flow's outcome as an MCP result (issue #904): its plain serialisation,
/// the object `--json` prints, plus the chat envelope its [`Report`]
/// methods produce (`summary`, `next_step`).
pub fn report<R: Report>(outcome: &R, model: &Model) -> Value {
    let mut value = serde_json::to_value(outcome)
        .unwrap_or_else(|err| refused(format!("the result could not be serialised: {err}")));
    envelope(&mut value, outcome.summary(model), outcome.next_step());
    value
}

/// Adds the chat envelope's `summary` and `next_step` to `value`, each when
/// there is one.
pub fn envelope(value: &mut Value, summary: Option<String>, next_step: Option<String>) {
    if let Some(map) = value.as_object_mut() {
        if let Some(summary) = summary {
            map.insert("summary".to_string(), Value::String(summary));
        }
        if let Some(next) = next_step {
            map.insert("next_step".to_string(), Value::String(next));
        }
    }
}

/// Adds the job fields of the envelope: the job id, whether the call
/// started it (`started: true`, still running) or saw it end (`done`).
pub fn with_job(value: &mut Value, job: &str, started: bool, done: bool) {
    if let Some(map) = value.as_object_mut() {
        map.insert("started".to_string(), Value::Bool(started));
        map.insert("done".to_string(), Value::Bool(done));
        map.insert("job".to_string(), Value::String(job.to_string()));
    }
}

/// [`report`] as a tool result.
pub fn ok_report<R: Report>(outcome: &R, model: &Model) -> Result<CallToolResult, ErrorData> {
    ok(report(outcome, model))
}

/// A structured tool result.
pub fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// The JSON of a refusal: `ok: false`, `refused: true` and the reason, a
/// normal result rather than a protocol error, so the assistant reads the
/// reason out to the human.
pub fn refused(reason: impl Into<String>) -> Value {
    serde_json::to_value(Refusal::new(reason)).unwrap_or_default()
}

/// [`refused`] about `key: value` (an `address`, a `line`, a `ga`).
pub fn refused_on(key: &str, value: &str, reason: impl Into<String>) -> Value {
    let mut out = refused(reason);
    out[key] = json!(value);
    out
}

/// [`refused`] as a tool result.
pub fn refusal(reason: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    ok(refused(reason))
}

/// A bad-argument error (an invalid address, an unknown value).
pub fn invalid(msg: impl Into<String>) -> ErrorData {
    ErrorData::invalid_params(msg.into(), None)
}

/// Copies every field of `extra` into `into` (both objects).
pub fn merge(into: &mut Value, extra: Value) {
    if let (Some(into), Value::Object(extra)) = (into.as_object_mut(), extra) {
        into.extend(extra);
    }
}

/// [`answer_on`] for a tool whose answer, refusal included, carries the
/// homeowner's `summary` (issue #306): a refusal says nothing changed.
pub fn answer_chat(
    key: &str,
    value: &str,
    result: Result<Value, String>,
    model: &Model,
) -> Result<CallToolResult, ErrorData> {
    ok(result.unwrap_or_else(|reason| {
        let refusal = Refusal {
            address: (key == "address").then(|| value.to_string()),
            line: (key == "line").then(|| value.to_string()),
            ..Refusal::new(reason)
        };
        let mut out = report(&refusal, model);
        if key != "address" && key != "line" {
            out[key] = json!(value);
        }
        out
    }))
}

/// The result of a tool body: its value, or [`refused`] with the reason.
pub fn answer(result: Result<Value, String>) -> Result<CallToolResult, ErrorData> {
    ok(result.unwrap_or_else(refused))
}

/// [`answer`] with a refusal about `key: value` ([`refused_on`]).
pub fn answer_on(
    key: &str,
    value: &str,
    result: Result<Value, String>,
) -> Result<CallToolResult, ErrorData> {
    ok(result.unwrap_or_else(|reason| refused_on(key, value, reason)))
}
