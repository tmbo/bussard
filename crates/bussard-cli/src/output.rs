//! Machine-readable output (`--json`, issue #228).
//!
//! Every JSON document a command prints is one object whose first field is
//! `"schema": <n>`, the version of that command's shape. `monitor --json`
//! prints JSON Lines; each line carries the field. A report that is a list
//! (`validate`, `history`) is wrapped in an object under a named key.
//!
//! Bump rules: a shape's number goes up when a field is removed or renamed,
//! changes its type, or changes its meaning. Adding a field does not bump it,
//! so a consumer must ignore fields it does not know. Every shape starts at 1.

use bussard_service::report::Report;
use serde::Serialize;

/// The schema version of each `--json` shape without a typed report yet;
/// a typed one carries its own ([`Report::SCHEMA`]).
pub use bussard_service::report::schema;

/// A JSON document: the schema version first, then the body's fields.
#[derive(Serialize)]
struct Document<'a, T: Serialize + ?Sized> {
    /// The shape's version, from [`schema`].
    schema: u32,
    /// The report; must serialize as an object (a struct or a map).
    #[serde(flatten)]
    body: &'a T,
}

/// Renders `body` (an object) as a pretty JSON document carrying `"schema"`.
///
/// # Errors
///
/// When `body` does not serialize as an object (a list must be wrapped under
/// a key first) or fails to serialize.
pub fn render<T: Serialize + ?Sized>(schema: u32, body: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(&Document { schema, body })?)
}

/// Prints `body` to stdout as a JSON document carrying `"schema"`.
///
/// # Errors
///
/// As [`render`].
pub fn print<T: Serialize + ?Sized>(schema: u32, body: &T) -> anyhow::Result<()> {
    println!("{}", render(schema, body)?);
    Ok(())
}

/// Prints a flow's typed outcome (issue #904) as its JSON document, under
/// the schema version declared next to its struct.
///
/// # Errors
///
/// As [`render`].
pub fn report<R: Report>(body: &R) -> anyhow::Result<()> {
    print(R::SCHEMA, body)
}

/// Adds `"schema"` as the first field of one JSON Lines object that was
/// rendered elsewhere (`monitor`), leaving every other byte as it was.
pub fn with_schema_line(schema: u32, line: &str) -> String {
    match line.strip_prefix('{') {
        Some(rest) if rest.trim_start().starts_with('}') => format!("{{\"schema\":{schema}}}"),
        Some(rest) => format!("{{\"schema\":{schema},{rest}"),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_puts_schema_first() -> anyhow::Result<()> {
        let text = render(3, &serde_json::json!({ "b": 1, "a": 2 }))?;
        let value: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(value["schema"], 3);
        assert_eq!(value["a"], 2);
        assert!(
            text.trim_start().starts_with("{\n  \"schema\": 3"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn test_render_refuses_a_list() {
        assert!(render(1, &serde_json::json!([1, 2])).is_err());
    }

    #[test]
    fn test_with_schema_line_prefixes_the_object() -> anyhow::Result<()> {
        let line = with_schema_line(1, r#"{"ga":"1/2/3","value":true}"#);
        assert_eq!(line, r#"{"schema":1,"ga":"1/2/3","value":true}"#);
        let value: serde_json::Value = serde_json::from_str(&line)?;
        assert_eq!(value["schema"], 1);
        assert_eq!(with_schema_line(2, "{}"), r#"{"schema":2}"#);
        Ok(())
    }
}
