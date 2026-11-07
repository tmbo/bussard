//! The reply helpers every tool shares (issue #905): a structured result, a
//! refusal the assistant reads out, a bad-argument error, and merging
//! result fields.

use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use serde_json::{Value, json};

/// A structured tool result.
pub fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// The JSON of a refusal: `ok: false`, `refused: true` and the reason, a
/// normal result rather than a protocol error, so the assistant reads the
/// reason out to the human.
pub fn refused(reason: impl Into<String>) -> Value {
    json!({ "ok": false, "refused": true, "reason": reason.into() })
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
