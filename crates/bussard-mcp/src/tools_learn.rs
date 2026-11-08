//! The learn and acceptance-test tools (issues #95 and #101).
//!
//! These live in their own `#[tool_router]` block so the read/write tiers in
//! [`crate::server`] stay untouched; [`BussardMcp::new`] combines the two
//! routers.
//!
//! - `knx_infer_group` is a **read-tier** tool and stays registered in
//!   `--passive` mode: it only reads the telegram ring and the model, and
//!   transmits nothing. It is the inference half of the conversational learn
//!   loop: the assistant asks the human to press a button, calls
//!   `knx_wait_for_telegram`, then calls this to get DPT candidates, the sending
//!   device, channel and com object, and a proposed name. The human confirms in
//!   chat and the assistant writes the result into the model. A secured group
//!   telegram (KNX Data Secure) reaches the ring decrypted when the server has
//!   a keyring (issue #205); one that did not verify carries ciphertext, so it
//!   is counted and left out of the inference.
//! - `knx_run_tests` is a **write-tier** tool, registered only with
//!   `--allow-writes`, and it refuses any test that writes to a protected group
//!   address whatever `tests.toml` says. There is no MCP override for a
//!   protected GA, ever.

use crate::args::Parameters;
use crate::reply::{invalid, ok, ok_report};
use bussard_model::GroupAddress;
use bussard_model::tests_schema;
use bussard_model::text::from_hex;
use bussard_service::acceptance::TestRunReport;
use bussard_service::acceptance::{self, RunOptions, SkipManual};
use bussard_service::learn::InferReport;
use bussard_service::monitor::Filter;
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::json;

use crate::server::BussardMcp;

/// Arguments for `knx_infer_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct InferArgs {
    /// A 3-level group address like `"1/0/12"`.
    pub ga: String,
    /// An explicit payload in hex (`"01"`, `"0c 1a"`) to infer from, instead of
    /// the telegrams already seen on this GA. Use it to ask about a payload you
    /// read out of a telegram yourself.
    #[serde(default)]
    pub payload_hex: Option<String>,
}

/// Arguments for `knx_run_tests`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct RunTestsArgs {
    /// Run only the tests with these names (as written in `tests.toml`,
    /// case-insensitive). Omit to run the whole file.
    #[serde(default)]
    pub only: Option<Vec<String>>,
}

#[tool_router(router = learn_router, vis = "pub(crate)")]
impl BussardMcp {
    // `knx_infer_group` (read tier; available in `--passive` too).
    #[doc = include_str!("../guidance/tools/knx_infer_group.md")]
    #[tool]
    async fn knx_infer_group(
        &self,
        Parameters(args): Parameters<InferArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ga: GroupAddress = args
            .ga
            .parse()
            .map_err(|_| invalid(format!("invalid group address {:?}", args.ga)))?;
        let model = self.state().model.current();

        // Payloads to reason about: the explicit one, else every group-value
        // payload seen on this GA, oldest first so `refine` narrows in order.
        let filter = Filter::parse(&ga.to_string()).map_err(|e| invalid(e.to_string()))?;
        let mut seen = self.state().ring.recent(&filter, None);
        seen.reverse();
        let seen: Vec<_> = seen
            .into_iter()
            .filter(|t| t.destination.group() == Some(ga))
            .collect();
        // A secured telegram that did not verify (no group key, MAC failure)
        // still carries the A_SecureData ciphertext: never infer from it.
        let undecrypted = seen
            .iter()
            .filter(|t| t.secure.as_ref().is_some_and(|s| !s.verified()))
            .count();
        let secured = seen
            .iter()
            .any(|t| t.secure.as_ref().is_some_and(|s| s.verified()));
        let seen: Vec<_> = seen
            .into_iter()
            .filter(|t| t.secure.as_ref().is_none_or(|s| s.verified()))
            .collect();

        let payloads: Vec<Vec<u8>> = match &args.payload_hex {
            Some(hex) => {
                let payload = parse_hex(hex)
                    .ok_or_else(|| invalid(format!("payload_hex {hex:?} is not valid hex")))?;
                vec![payload]
            }
            None => seen
                .iter()
                .map(|t| t.payload.clone())
                .filter(|p| !p.is_empty())
                .collect(),
        };

        // The sender is the source of the most recent telegram on the GA.
        let sender = seen.last().map(|t| t.source);
        let observation = bussard_service::learn::observe(&model, ga, sender, &payloads);
        let report = InferReport::new(
            &model,
            ga,
            sender,
            &payloads,
            observation,
            (secured, undecrypted),
        );
        ok_report(&report, &model)
    }

    // `knx_run_tests` (registered only with `--allow-writes`).
    #[doc = include_str!("../guidance/tools/knx_run_tests.md")]
    #[tool]
    async fn knx_run_tests(
        &self,
        Parameters(args): Parameters<RunTestsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        if state.passive || !state.allow_writes {
            return ok(json!({
                "ok": false,
                "reason": "bus writes are disabled on this server; start it with --allow-writes",
            }));
        }

        let suite = match tests_schema::load_tests_in_dir(&state.dir) {
            Ok(Some(suite)) => suite,
            Ok(None) => {
                return ok(json!({
                    "ok": false,
                    "reason": format!(
                        "no {} in the model directory {}; write one first (see `bussard test` in \
                         the reference)",
                        tests_schema::TESTS_FILE,
                        state.dir.display()
                    ),
                }));
            }
            Err(err) => {
                return ok(json!({
                    "ok": false,
                    "reason": format!("could not load the test file: {err}"),
                }));
            }
        };

        let model = state.model.current();

        // Name the protected tests up front so the report says plainly which
        // ones an MCP run can never cover.
        let refused: Vec<String> = suite
            .tests
            .iter()
            .filter(|t| acceptance::touches_protected(&model, t))
            .map(|t| t.name.clone())
            .collect();

        let handle = match state.live_service(crate::state::Need::Write) {
            Ok(service) => service.handle(),
            Err(reason) => {
                return ok(json!({
                    "ok": false,
                    "reason": reason,
                    "bus": state.bus.to_json(),
                    "refused_protected": refused,
                }));
            }
        };

        // A whole suite is a burst of bus writes: hold one rate-limiter permit
        // across the run, as the introspection tool does.
        let _permit = state.read_limiter.acquire().await;

        let options = RunOptions {
            only: args.only.clone(),
            // Never set over MCP. A protected GA needs a human at a terminal.
            allow_protected: false,
        };
        let mut manual = SkipManual {
            reason: "manual step: run `bussard test` from a terminal so a human can carry it out"
                .to_string(),
        };
        let report =
            acceptance::run_suite(&suite, &model, handle, &state.ring, &options, &mut manual).await;

        let report = TestRunReport {
            refused_protected: refused,
            ..TestRunReport::of(&report)
        };
        ok_report(&report, &model)
    }
}

/// Parses a hex payload such as `"01"`, `"0x0c1a"` or `"0c 1a"`.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    from_hex(&cleaned).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_forms() {
        assert_eq!(parse_hex("01"), Some(vec![1]));
        assert_eq!(parse_hex("0x0c1a"), Some(vec![0x0c, 0x1a]));
        assert_eq!(parse_hex("0c 1a"), Some(vec![0x0c, 0x1a]));
        assert_eq!(parse_hex("xyz"), None);
        assert_eq!(parse_hex("1"), None);
    }
}
