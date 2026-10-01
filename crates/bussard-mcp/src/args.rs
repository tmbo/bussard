//! The tool-argument extractor (issue #269).
//!
//! rmcp's own `Parameters<T>` turns a `tools/call` request that carries no
//! `arguments` member into an empty object, so a client that drops the
//! arguments produces "missing field `address`", which the assistant reads as a
//! server bug. [`Parameters`] here replaces it on every bussard tool and says
//! what actually reached the server: no arguments, an empty object, or a real
//! serde error, each followed by the fields the tool expects.
//!
//! The type keeps rmcp's name on purpose: the `#[tool]` macro finds the
//! argument type by the last path segment `Parameters` and derives the tool's
//! `inputSchema` from it, so the schema keeps coming from `T: JsonSchema`.

use std::borrow::Cow;

use rmcp::ErrorData;
use rmcp::handler::server::common::{FromContextPart, schema_for_type};
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::schemars::{self, JsonSchema};
use serde::de::DeserializeOwned;

/// The arguments of one tool call, deserialized into `P`.
///
/// A drop-in replacement for `rmcp::handler::server::wrapper::Parameters`
/// whose deserialization errors tell the caller what the server received and
/// which fields the tool expects.
#[derive(Debug, Clone)]
pub struct Parameters<P>(pub P);

impl<P: JsonSchema> JsonSchema for Parameters<P> {
    fn schema_name() -> Cow<'static, str> {
        P::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        P::json_schema(generator)
    }
}

impl<S, P> FromContextPart<ToolCallContext<'_, S>> for Parameters<P>
where
    P: DeserializeOwned + JsonSchema + 'static,
{
    fn from_context_part(context: &mut ToolCallContext<'_, S>) -> Result<Self, ErrorData> {
        let arguments = context.arguments.take();
        let present = arguments.is_some();
        let fields: Vec<String> = field_names(arguments.as_ref())
            .into_iter()
            .map(str::to_string)
            .collect();
        deserialize_arguments::<P>(arguments)
            .map(Parameters)
            .inspect_err(|_| {
                // Warn, so the evidence reaches the client's server log at the
                // default level. Field names only: the error text can quote a
                // value, and values may be secrets.
                tracing::warn!(
                    tool = %context.name(),
                    arguments_present = present,
                    fields = ?fields,
                    "tools/call arguments rejected"
                );
            })
    }
}

/// Deserializes a tool call's `arguments` member into `P`, or explains the
/// failure in terms the calling assistant can act on.
///
/// A missing member is treated as an empty object first, so a tool whose
/// fields are all optional still runs without arguments; only when that fails
/// does the error say that the client sent none.
///
/// # Errors
///
/// An `invalid_params` error naming what was received and the expected fields.
pub fn deserialize_arguments<P>(arguments: Option<rmcp::model::JsonObject>) -> Result<P, ErrorData>
where
    P: DeserializeOwned + JsonSchema + 'static,
{
    let present = arguments.is_some();
    let object = arguments.unwrap_or_default();
    let empty = object.is_empty();
    serde_path_to_error::deserialize::<_, P>(serde_json::Value::Object(object)).map_err(|e| {
        let expected = expected_fields::<P>();
        let message = if !present {
            format!(
                "the call reached bussard without any arguments (the client sent none); \
                 expected fields: {expected}; retry with the arguments as a JSON object"
            )
        } else if empty {
            format!(
                "the call reached bussard with an empty object as its arguments; \
                 expected fields: {expected}; retry with the arguments as a JSON object"
            )
        } else {
            format!("failed to deserialize parameters: {e}; expected fields: {expected}")
        };
        ErrorData::invalid_params(message, None)
    })
}

/// The fields `P` accepts, read from its JSON schema: the required ones first
/// in schema order, then the optional ones marked `(optional)`.
fn expected_fields<P: JsonSchema + 'static>() -> String {
    let schema = schema_for_type::<P>();
    let required: Vec<&str> = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .map(|names| names.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    let mut fields: Vec<String> = required.iter().map(|name| (*name).to_string()).collect();
    if let Some(properties) = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
    {
        fields.extend(
            properties
                .keys()
                .filter(|name| !required.contains(&name.as_str()))
                .map(|name| format!("{name} (optional)")),
        );
    }
    if fields.is_empty() {
        "none (see the tool's inputSchema)".to_string()
    } else {
        fields.join(", ")
    }
}

/// The start of the two messages for a call whose arguments never arrived.
const NOT_RECEIVED_PREFIX: &str = "the call reached bussard ";

/// Turns an argument error from [`Parameters`] into a tool result with
/// `isError` set, which the assistant reads and can act on, and passes every
/// other outcome through.
///
/// rmcp already does this for serde errors (their text starts with "failed to
/// deserialize parameters:"); the no-arguments and empty-object messages need
/// the same treatment, or a client would show them as a protocol failure.
///
/// # Errors
///
/// Any error that is not a bussard argument error, unchanged.
pub fn argument_error_as_tool_result(
    result: Result<rmcp::model::CallToolResponse, ErrorData>,
) -> Result<rmcp::model::CallToolResponse, ErrorData> {
    match result {
        Err(error)
            if error.code == rmcp::model::ErrorCode::INVALID_PARAMS
                && error.message.starts_with(NOT_RECEIVED_PREFIX) =>
        {
            Ok(
                rmcp::model::CallToolResult::error(vec![rmcp::model::ContentBlock::text(
                    error.message,
                )])
                .into(),
            )
        }
        other => other,
    }
}

/// The top-level field names of a tool call's arguments, for logging. Values
/// are never included: they may carry passwords or key material.
pub fn field_names(arguments: Option<&rmcp::model::JsonObject>) -> Vec<&str> {
    arguments
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// A copy of a JSON value with every string replaced by `"<redacted>"`, for the
/// debug log of a raw request. Numbers, booleans and the structure stay.
pub fn redact_strings(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(_) => serde_json::Value::String("<redacted>".to_string()),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_strings).collect())
        }
        serde_json::Value::Object(object) => serde_json::Value::Object(
            object
                .iter()
                .map(|(key, item)| (key.clone(), redact_strings(item)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Deserialize, JsonSchema)]
    struct Link {
        address: String,
        com_object: u16,
        #[serde(default)]
        note: Option<String>,
    }

    #[derive(Debug, Deserialize, JsonSchema)]
    struct AllOptional {
        #[serde(default)]
        since: Option<String>,
    }

    fn object(value: serde_json::Value) -> Option<rmcp::model::JsonObject> {
        value.as_object().cloned()
    }

    #[test]
    fn test_deserialize_arguments_absent_names_fields() {
        let err = deserialize_arguments::<Link>(None)
            .err()
            .map(|e| e.message.to_string());
        assert_eq!(
            err.as_deref(),
            Some(
                "the call reached bussard without any arguments (the client sent none); \
                 expected fields: address, com_object, note (optional); \
                 retry with the arguments as a JSON object"
            )
        );
    }

    #[test]
    fn test_deserialize_arguments_empty_object() {
        let err = deserialize_arguments::<Link>(object(json!({})))
            .err()
            .map(|e| e.message.to_string())
            .unwrap_or_default();
        assert!(err.contains("with an empty object"), "{err}");
    }

    #[test]
    fn test_deserialize_arguments_wrong_type_names_field() {
        let err = deserialize_arguments::<Link>(object(
            json!({"address": "1.1.4", "com_object": "seven"}),
        ))
        .err()
        .map(|e| e.message.to_string())
        .unwrap_or_default();
        assert!(
            err.contains("com_object: invalid type: string \"seven\""),
            "{err}"
        );
        assert!(
            err.contains("expected fields: address, com_object"),
            "{err}"
        );
    }

    #[test]
    fn test_deserialize_arguments_valid() -> Result<(), ErrorData> {
        let link =
            deserialize_arguments::<Link>(object(json!({"address": "1.1.4", "com_object": 7})))?;
        assert_eq!(
            (link.address.as_str(), link.com_object, link.note),
            ("1.1.4", 7, None)
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_arguments_absent_but_all_optional() -> Result<(), ErrorData> {
        let args = deserialize_arguments::<AllOptional>(None)?;
        assert!(args.since.is_none());
        Ok(())
    }

    #[test]
    fn test_redact_strings_keeps_structure() {
        let raw =
            json!({"name": "knx_x", "arguments": {"password": "secret", "n": 7, "l": ["a", true]}});
        let redacted = redact_strings(&raw);
        assert_eq!(
            redacted,
            json!({"name": "<redacted>", "arguments": {"password": "<redacted>", "n": 7, "l": ["<redacted>", true]}})
        );
    }
}
