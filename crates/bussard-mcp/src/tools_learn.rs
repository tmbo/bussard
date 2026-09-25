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

use bussard_model::tests_schema;
use bussard_model::{Dpt, GroupAddress};
use bussard_monitor::Filter;
use bussard_monitor::acceptance::{self, RunOptions, SkipManual};
use bussard_monitor::infer;
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::server::BussardMcp;
use crate::state::ConnState;

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

/// The guidance `knx_infer_group` returns so the assistant closes the loop with
/// the human rather than writing a guess into the model.
const NEXT_STEP: &str = "Tell the human what you think this group address is \
    (the proposed name and the top DPT candidate, in their words, e.g. \"that looks like the \
    kitchen ceiling light switch\") and ASK them to confirm or correct it. Only after they \
    answer, write the result into the model: knx_set_group for the name and DPT, and \
    knx_add_link for the sending device's com object when a sender is known. If the candidates \
    are not confident enough, ask the human to trigger the same object again and call this tool \
    once more; repeated observations narrow the candidate set.";

/// Turns a JSON value into a structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A bad-argument error.
fn invalid(msg: impl Into<String>) -> ErrorData {
    ErrorData::invalid_params(msg.into(), None)
}

#[tool_router(router = learn_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_infer_group` (read tier; available in `--passive` too).
    #[tool(
        description = "Infer what a group address IS from the traffic already seen on it: ranked \
        DPT candidates with the reasoning for each, the sending device (address, name, location), \
        its channel and com object (index, name, declared DPT, flags), the model's current entry \
        for the GA, and a proposed human name built from location, channel and com-object \
        function. This is the second half of the learn loop: ask the human to press the button, \
        call knx_wait_for_telegram, then call this. It reads the telegram buffer and the model \
        only and NEVER transmits, so it works in --passive mode. Confidence is never 'high' \
        unless the sending com object declares the DPT. Pass payload_hex to ask about a specific \
        payload instead of the buffered ones. Secured (KNX Data Secure) telegrams count only when \
        the server's --keyring decrypted them (`secured`: true); `undecrypted_secured` counts the \
        ones left out."
    )]
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
        let object = sender.and_then(|ia| infer::sending_object(&model, ia, ga));
        let declared = object.as_ref().and_then(|o| o.declared_dpt);

        let candidates = match payloads.split_first() {
            Some((first, rest)) => infer::refine(infer::infer_dpt(first, declared), rest),
            // Nothing seen yet: still report what the model knows, with the
            // declared DPT as the only candidate.
            None => match declared {
                Some(dpt) => infer::infer_dpt(&placeholder_payload(dpt), Some(dpt)),
                None => Vec::new(),
            },
        };

        // With no link in the model there is no com-object index; `u16::MAX` is
        // an index no com object uses, so the proposal falls back to the
        // device's own name and location.
        let proposed_name = sender.and_then(|ia| {
            infer::propose_name(
                &model,
                ia,
                object.as_ref().map(|o| o.index).unwrap_or(u16::MAX),
            )
        });

        let group = model.groups.groups.get(&ga).map(|g| {
            json!({
                "name": g.name,
                "dpt": g.dpt.map(|d| d.to_string()),
                "description": g.description,
                "protected": g.protected,
            })
        });

        let sender_json = sender.map(|ia| {
            let device = model.devices.get(&ia).map(|d| &d.device);
            json!({
                "address": ia.to_string(),
                "name": device.map(|d| d.name.clone()),
                "location": device.and_then(|d| d.location.as_ref()).map(|l| json!({
                    "floor": l.floor,
                    "room": l.room,
                })),
                "known_to_the_model": device.is_some(),
            })
        });

        ok(json!({
            "ga": ga.to_string(),
            "group": group,
            "observations": payloads.len(),
            "payloads_hex": payloads.iter().map(|p| hex(p)).collect::<Vec<_>>(),
            "sender": sender_json,
            "channel": object.as_ref().map(|o| json!({
                "key": o.channel_key,
                "name": o.channel_name,
            })),
            "com_object": object.as_ref().map(|o| json!({
                "index": o.index,
                "name": o.name,
                "declared_dpt": o.declared_dpt.map(|d| d.to_string()),
                "flags": o.flags.map(|f| f.to_string()),
            })),
            "candidates": candidates.iter().map(|c| json!({
                "dpt": c.dpt.to_string(),
                "confidence": c.confidence.tag(),
                "reason": c.reason,
            })).collect::<Vec<_>>(),
            "proposed_name": proposed_name,
            "secured": secured,
            "undecrypted_secured": undecrypted,
            "secure_note": (undecrypted > 0).then(|| format!(
                "{undecrypted} secured telegram(s) on {ga} did not decrypt and were left out: \
                 {} (restart `bussard mcp` with it)",
                bussard_service::guidance::group_key_hint()
            )),
            "next_step": NEXT_STEP,
        }))
    }

    /// `knx_run_tests` (registered only with `--allow-writes`).
    #[tool(
        description = "Run the acceptance tests in the model directory's tests.toml against the \
        PHYSICAL bus and return a pass/fail report. Each test writes a group value and waits for \
        the telegram that proves the installation reacted, so actuators MOVE. Only available when \
        the server was started with --allow-writes. A test that writes to a protected group \
        address (a wind alarm, a central function) is REFUSED and not run, whatever the file's \
        allow_protected flag says. There is no MCP override; a human must run `bussard test \
        --force` from a terminal. Tests with a `manual:` step are skipped here, since nobody is \
        at the server's terminal to carry them out. Use `only` to run named tests."
    )]
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

        let Some(handle) = state.bus.handle() else {
            return ok(json!({
                "ok": false,
                "reason": "bus is not wired",
                "bus": state.bus.to_json(),
                "refused_protected": refused,
            }));
        };
        if state.bus.state() != ConnState::Connected {
            return ok(json!({
                "ok": false,
                "reason": "bus is not connected",
                "bus": state.bus.to_json(),
                "refused_protected": refused,
            }));
        }

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

        let mut value = report.to_json();
        value["ok"] = json!(report.ok());
        value["refused_protected"] = json!(refused);
        ok(value)
    }
}

/// A payload of the right width for `dpt`, used only to seed the candidate list
/// when the ring has seen nothing yet.
fn placeholder_payload(dpt: Dpt) -> Vec<u8> {
    match dpt.expected_size() {
        Some(bussard_model::ApduSize::Bits(_)) => vec![0],
        Some(bussard_model::ApduSize::Bytes(n)) => vec![0; n as usize],
        None => vec![0],
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
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

/// Renders payload bytes as lowercase hex.
fn hex(payload: &[u8]) -> String {
    payload.iter().map(|b| format!("{b:02x}")).collect()
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

    #[test]
    fn test_placeholder_payload_matches_the_dpt_width() {
        assert_eq!(placeholder_payload(Dpt::new(1, Some(1))).len(), 1);
        assert_eq!(placeholder_payload(Dpt::new(9, Some(1))).len(), 2);
        assert_eq!(placeholder_payload(Dpt::new(16, Some(1))).len(), 14);
    }

    #[test]
    fn test_next_step_names_the_model_edit_tools() {
        assert!(NEXT_STEP.contains("knx_set_group"));
        assert!(NEXT_STEP.contains("knx_add_link"));
    }
}
