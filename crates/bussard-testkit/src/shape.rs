//! One JSON shape per flow (issue #904): the check that a flow's MCP result
//! is its `--json` document plus the chat envelope and nothing else.

use serde_json::Value;

/// The keys only an MCP result carries beyond a flow's `--json` document:
/// the chat envelope (`summary`, `what_you_will_notice`, `next_step`), the
/// job fields (`job`, `started`, `done`, `record`), and what only a server
/// session has (the plan digest, its expiry, the session's pending edits).
pub const MCP_ONLY: &[&str] = &[
    "summary",
    "next_step",
    "what_you_will_notice",
    "job",
    "started",
    "done",
    "record",
    "plan_digest",
    "expires_at",
    "pending_model_changes",
];

/// Checks that `mcp` is `cli` (a `--json` document) plus the keys in
/// [`MCP_ONLY`]: every key of `cli` but `schema` and `volatile` (a time
/// stamp of the run) is in `mcp` with the same value, and `mcp` has no other
/// key. `Err` names the first difference.
///
/// # Errors
///
/// The first key that differs, is missing, or is extra.
pub fn assert_one_shape(cli: &Value, mcp: &Value, volatile: &[&str]) -> Result<(), String> {
    let (Some(cli), Some(mcp)) = (cli.as_object(), mcp.as_object()) else {
        return Err(format!("not two objects: {cli} / {mcp}"));
    };
    for (key, value) in cli {
        if key == "schema" || volatile.contains(&key.as_str()) {
            continue;
        }
        match mcp.get(key) {
            None => return Err(format!("`{key}` is in --json but not in the MCP result")),
            Some(other) if other != value => {
                return Err(format!(
                    "`{key}` differs: --json has {value}, the MCP result has {other}"
                ));
            }
            Some(_) => {}
        }
    }
    for key in mcp.keys() {
        if !cli.contains_key(key) && !MCP_ONLY.contains(&key.as_str()) {
            return Err(format!(
                "`{key}` is in the MCP result but not in --json, and is not envelope"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_assert_one_shape_allows_only_the_envelope() {
        let cli = json!({"schema": 2, "address": "1.1.4", "noop": false, "at": "t1"});
        let mcp = json!({"address": "1.1.4", "noop": false, "at": "t2", "summary": "s"});
        assert!(assert_one_shape(&cli, &mcp, &["at"]).is_ok());
        let extra = json!({"address": "1.1.4", "noop": false, "plan": "x"});
        assert!(assert_one_shape(&cli, &extra, &["at"]).is_err());
        let differs = json!({"address": "1.1.5", "noop": false});
        assert!(assert_one_shape(&cli, &differs, &["at"]).is_err());
    }
}
