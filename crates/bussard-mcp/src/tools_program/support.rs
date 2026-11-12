//! The supported-device gate over MCP (issue #1089): every device write tool
//! asks [`bussard_service::support::authorize`], the function the CLI asks.
//!
//! The override reaches a write one of two ways, decided by the client
//! (issue #1093):
//!
//! - A client with form-mode elicitation: bussard asks the human itself
//!   ("1.1.7 is not on the supported list. Write anyway?"), through the
//!   client and past the assistant, so the assistant cannot answer for them.
//!   `allow_unsupported` from the assistant does not count then.
//! - A client without it: `allow_unsupported: true`, which counts only with
//!   the digest of a plan that reported the device unsupported, so the
//!   assistant has seen the warning and put it to the human; it is the trust
//!   model of every other confirmed write (#905).
//!
//! A refusal is a normal result with the code `unsupported_device`; nothing is
//! written and the digest stays valid. [`BussardMcp::support_override`] is the
//! one helper `knx_apply_device`, `knx_restore_parameters`,
//! `knx_restore_tables` and `knx_replace_device` decide through.

use std::collections::BTreeMap;

use bussard_model::{IndividualAddress, Model};
use bussard_service::report::Refusal;
use bussard_service::support::{self, SupportGrant, SupportRefusal};
use bussard_service::transport::ConnectionConfig;
use rmcp::model::{
    CallToolResponse, ElicitRequestParams, ElicitationAction, ElicitationSchema, InputResponses,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use serde_json::{Value, json};

use crate::elicit::{self, Shown};
use crate::server::BussardMcp;

/// The refusal code of a write to a device not on the supported list.
pub(crate) const UNSUPPORTED_DEVICE: &str = "unsupported_device";

/// The key of the question in a multi round-trip call's `inputRequests`.
const INPUT_KEY: &str = "unsupported_device";

/// The prefix of the request state that names a pending question.
const REQUEST_STATE_PREFIX: &str = "bussard-unsupported:";

/// A write the support gate refused: the device is not rated `proven` or
/// `likely` (not listed, or a listed known problem, issue #1097) and the
/// override was not given (or not with a plan that reported it). A `likely`
/// device passes the gate, so it is never asked about or refused here.
pub(crate) struct Refused(SupportRefusal);

/// The support gate of a write of `target` that builds its image from
/// `application` (the program its product data selects, `None` without
/// product data); `allow_unsupported` counts only when
/// `plan_reported_unsupported`, the plan the digest names said so.
pub(crate) fn gate(
    connection: &ConnectionConfig,
    model: &Model,
    target: IndividualAddress,
    application: Option<&str>,
    (allow_unsupported, plan_reported_unsupported): (bool, bool),
) -> Result<SupportGrant, Refused> {
    support::authorize(
        connection,
        target,
        model.devices.get(&target).map(|d| &d.device),
        application,
        allow_unsupported && plan_reported_unsupported,
    )
    .map_err(Refused)
}

/// The support gate of a write before its job, with the override given or
/// not: `Ok(None)` passes, `Ok(Some(_))` is the gate's refusal, `Err` is
/// another refusal the write answers anyway (an unknown or expired digest,
/// a digest for another subject, a busy bus slot), which bussard never asks
/// the human about.
pub(crate) type Check = Result<Option<Refused>, String>;

/// How the override was sought when a write is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    /// The client cannot ask the human: `allow_unsupported` is the override.
    Flag,
    /// bussard asked the human; `shown` is false when the client did not
    /// show the question.
    Asked {
        /// Whether the client showed the question.
        shown: bool,
    },
    /// The plan the digest names did not report the device unsupported, so
    /// no override counts: plan again.
    Replan,
}

impl Refused {
    /// The pre-flight's refusal when it judges the write on what is true
    /// then and the check before the job passed: the product data (or the
    /// device's application) changed since the plan, so the same call can
    /// only repeat. The caller retires the digest.
    pub(crate) fn moved(&self) -> String {
        format!(
            "refusing to write {}: the product data changed since the plan was made, and now {}. \
             Nothing was written. Plan again and show the new plan and its support verdict to \
             the human.",
            self.0.target,
            self.0.sentence()
        )
    }

    /// The question bussard puts to the human: the refusal's sentence (a
    /// known problem with its cause, as the issue states it), why it matters
    /// and the way back.
    fn question(&self) -> String {
        let why = if self.0.verdict.view().problem.is_some() {
            "Writing it anyway can leave the device not working."
        } else {
            "bussard has never checked what it writes to this product against ETS, and a wrong \
             image can leave the device not working."
        };
        format!(
            "{}. {why} Back the device up first; ETS is the safe way to program it. Write anyway?",
            self.0.sentence()
        )
    }

    /// The structured refusal: `ok: false`, `refused: true`, `code:
    /// unsupported_device`, the `support` verdict, the `override` (when one
    /// is left for the assistant to give) and the homeowner's summary.
    pub(crate) fn answer(&self, model: &Model, digest_kept: bool, via: Via) -> Value {
        let refusal = &self.0;
        let target = refusal.target.to_string();
        let declined = match via {
            Via::Asked { shown: true } => " The human declined.",
            Via::Asked { shown: false } => " The chat app did not show bussard's question.",
            Via::Flag | Via::Replan => "",
        };
        let reason = format!(
            "{}.{declined} Nothing was written.{}",
            refusal.sentence(),
            if digest_kept {
                " The plan_digest stays valid."
            } else {
                ""
            }
        );
        let mut out = crate::reply::report(
            &Refusal {
                address: Some(target.clone()),
                ..Refusal::new(reason)
            },
            model,
        );
        let next_step = next_step(&target, &refusal.verdict.view(), via);
        let mut extra = json!({
            "code": UNSUPPORTED_DEVICE,
            "support": refusal.verdict.view(),
            "next_step": next_step,
        });
        if via == Via::Flag {
            extra["override"] = json!("allow_unsupported: true");
        }
        crate::reply::merge(&mut out, extra);
        out
    }
}

/// What the assistant does after a refusal reached `via`. A listed known
/// problem is named with its cause as the issue gives it (the capture may be
/// at fault, not bussard); a device not on the list is one bussard has never
/// checked against ETS.
fn next_step(target: &str, view: &support::SupportView, via: Via) -> String {
    let what = match view.problem_text() {
        Some(problem) => {
            format!("{target} has a known problem on bussard's device-support list ({problem})")
        }
        None => format!("{target} is not on bussard's list of supported devices"),
    };
    match via {
        Via::Flag => format!(
            "Tell the human that {what}{}, and that a wrong image can leave the device not \
             working; say the cause as it stands. Recommend a backup first and ETS as the safe \
             way. Only if the human explicitly says to write anyway, call the same tool again \
             with the same plan_digest and allow_unsupported: true. Never decide this for them.",
            if view.problem.is_some() {
                ""
            } else {
                ": bussard has never checked what it writes to this product against ETS"
            }
        ),
        Via::Asked { shown: true } => format!(
            "The human said no to bussard's own question about writing {target}: {what}. Do not \
             write it; recommend ETS for this device. Call the tool again only if the human asks \
             to, and bussard asks them again."
        ),
        Via::Asked { shown: false } => format!(
            "{what}, and this chat app did not show bussard's question to the human. Nothing was \
             written. Call the tool again only if the human asks to; bussard asks them again."
        ),
        Via::Replan => format!(
            "{what}, and the plan this plan_digest names did not report that. Plan again, show \
             the new plan and its support verdict to the human, and only then call the write \
             again."
        ),
    }
}

/// What a write call carries for the human's answer to bussard's question:
/// the call's context and, in the second round of a multi round-trip call,
/// its request state and input responses.
pub(crate) struct Ask<'a> {
    /// The call's context: the client's capabilities and protocol.
    context: &'a RequestContext<RoleServer>,
    /// The request state of the second round, when this is one.
    request_state: Option<String>,
    /// The human's answers in the second round.
    responses: Option<InputResponses>,
}

impl<'a> Ask<'a> {
    /// The answer channel of one call.
    pub(crate) fn new(
        context: &'a RequestContext<RoleServer>,
        request_state: Option<String>,
        responses: Option<InputResponses>,
    ) -> Self {
        Ask {
            context,
            request_state,
            responses,
        }
    }

    /// Whether the client can put a question to the human: it declared
    /// form-mode elicitation (an elicitation capability without modes means
    /// form mode, as the MCP specification reads it).
    fn asks_human(&self) -> bool {
        self.context
            .client_capabilities()
            .and_then(|caps| caps.elicitation)
            .is_some_and(|e| e.form.is_some() || e.url.is_none())
    }
}

/// One write the override is decided for: the tool, its subject (a device,
/// a line, a job), the plan digest and the assistant's `allow_unsupported`.
/// bussard's question is bound to the first three: a second round answers
/// only the question it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Write {
    /// The tool.
    tool: &'static str,
    /// The device, line or job.
    subject: String,
    /// The plan digest the write presents.
    digest: String,
    /// `allow_unsupported` as the assistant passed it.
    flag: bool,
}

impl Write {
    /// The write of `tool` about `subject` with `digest` and `flag`.
    pub(crate) fn new(
        tool: &'static str,
        subject: impl ToString,
        digest: &str,
        flag: bool,
    ) -> Self {
        Write {
            tool,
            subject: subject.to_string(),
            digest: digest.to_string(),
            flag,
        }
    }

    /// The question's binding: the write without the assistant's flag.
    fn binding(&self) -> Write {
        Write {
            flag: false,
            ..self.clone()
        }
    }
}

/// How a write goes on after the support gate.
pub(crate) enum Override {
    /// Write, with the override (`true`) or without.
    Go(bool),
    /// A line write whose question the human declined (or that the client
    /// did not show): write the supported devices only, and say so.
    Declined {
        /// Whether the client showed the question.
        shown: bool,
    },
    /// Answer the call with this: a refusal, or the question for the client.
    Answer(Result<CallToolResponse, ErrorData>),
}

impl Override {
    /// The call's answer of an override that does not go on to the write.
    pub(crate) fn answer(self) -> Result<CallToolResponse, ErrorData> {
        match self {
            Override::Answer(answer) => answer,
            Override::Go(_) | Override::Declined { .. } => Err(ErrorData::internal_error(
                "the supported-device gate went on without an answer",
                None,
            )),
        }
    }
}

/// What the gate decides before anyone is asked.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Write, with the override or without.
    Go(bool),
    /// Refuse, saying how the override is sought.
    Refuse(Via),
    /// Ask the human.
    Ask,
}

/// The decision on the gate's verdict without the override (`plain`) and
/// with it (`forced`), each `true` when it refuses: a write the override
/// cannot pass is a plan-again refusal; otherwise the human is asked when
/// the client can, else the assistant's `flag` decides.
fn decide(asks_human: bool, flag: bool, plain: bool, forced: bool) -> Step {
    match (plain, forced) {
        (false, _) => Step::Go(false),
        (true, true) => Step::Refuse(Via::Replan),
        (true, false) if asks_human => Step::Ask,
        (true, false) if flag => Step::Go(true),
        (true, false) => Step::Refuse(Via::Flag),
    }
}

/// What became of bussard's question.
enum Asked {
    /// The human accepted.
    Yes,
    /// The human declined or dismissed it, or the client did not show it.
    No {
        /// Whether the client showed the question.
        shown: bool,
    },
    /// The client asks the human and calls again: answer with this.
    Pending(CallToolResponse),
}

/// `value` as a tool result.
fn respond(value: Value) -> Override {
    Override::Answer(crate::reply::ok(value).map(Into::into))
}

impl BussardMcp {
    /// The override of a device write (issue #1093). `check(allow)` is the
    /// write's support gate before its job ([`gate`]) after every check that
    /// can refuse without the bus; the write gate and the live service are
    /// checked here. A write one of those refuses goes on without the
    /// override and is refused by its own pre-flight: bussard asks only
    /// about a write nothing else stops. Without elicitation `flag`
    /// (`allow_unsupported`) is the override; with it, bussard asks the human
    /// and `flag` does not count. A declined or dismissed question is a
    /// refusal with nothing written and the digest kept.
    pub(crate) async fn support_override(
        &self,
        ask: Ask<'_>,
        write: Write,
        check: impl Fn(bool) -> Check,
    ) -> Override {
        let Ok(Some(refused)) = self.ready().and_then(|()| check(false)) else {
            return Override::Go(false);
        };
        let forced = !matches!(check(true), Ok(None));
        let model = self.state().model.current();
        match decide(ask.asks_human(), write.flag, true, forced) {
            Step::Go(allow) => Override::Go(allow),
            Step::Refuse(via) => respond(refused.answer(&model, true, via)),
            Step::Ask => match self.ask_human(&ask, &write, refused.question()).await {
                Asked::Yes => self.after_yes(&check),
                Asked::No { shown } => respond(refused.answer(&model, true, Via::Asked { shown })),
                Asked::Pending(response) => Override::Answer(Ok(response)),
            },
        }
    }

    /// The override of a line write (issue #1093): `unsupported` is whether
    /// the line plan the digest names reported a device a write refuses as
    /// not on the list. Without elicitation `flag` is the override; with it
    /// bussard asks the human, and a no writes the supported devices only
    /// ([`Override::Declined`]), as a write without the override does.
    pub(crate) async fn line_override(
        &self,
        ask: Ask<'_>,
        write: Write,
        unsupported: bool,
    ) -> Override {
        if !ask.asks_human() {
            return Override::Go(write.flag);
        }
        if !unsupported || self.ready().is_err() {
            return Override::Go(false);
        }
        let question = format!(
            "Line {} has devices bussard does not rate proven or likely: not on its list of \
             supported devices, or with a known problem (the plan names them and the causes). A \
             wrong image can leave a device not working. Back them up first; ETS is the safe way \
             to program them. Write them anyway? No writes the proven and likely devices only.",
            write.subject
        );
        match self.ask_human(&ask, &write, question).await {
            Asked::Yes => Override::Go(true),
            Asked::No { shown } => Override::Declined { shown },
            Asked::Pending(response) => Override::Answer(Ok(response)),
        }
    }

    /// The refusals a write answers before its job without the bus: the
    /// programming tier, the write gate, the live service.
    fn ready(&self) -> Result<(), String> {
        self.programming_preflight().map(|_| ())
    }

    /// The write after the human's yes: everything is checked again, since
    /// the question can outlast the plan lifetime or the bus.
    fn after_yes(&self, check: &impl Fn(bool) -> Check) -> Override {
        let model = self.state().model.current();
        match self.ready().and_then(|()| check(true)) {
            Ok(None) => Override::Go(true),
            Ok(Some(refused)) => respond(refused.answer(&model, false, Via::Replan)),
            Err(reason) => respond(crate::reply::refused(format!(
                "The human said yes to writing a device bussard does not rate proven or likely, \
                 but by then {reason}. Nothing was written."
            ))),
        }
    }

    /// Puts `message` to the human as a form-mode elicitation, by the
    /// transport of the call's protocol (see [`crate::elicit`]). The second
    /// round of a multi round-trip call answers the question its request
    /// state names, when that question was asked for `write`; any other
    /// state is asked afresh.
    async fn ask_human(&self, ask: &Ask<'_>, write: &Write, message: String) -> Asked {
        let Ok(tier) = self.tier() else {
            return Asked::No { shown: false };
        };
        let binding = write.binding();
        if let Some(id) = ask
            .request_state
            .as_deref()
            .and_then(|state| state.strip_prefix(REQUEST_STATE_PREFIX))
            && let Some(asked) = tier.support_questions.get(id)
        {
            // One question, one answer.
            tier.support_questions.retire(id);
            if asked == binding {
                return match elicit::answer(ask.responses.as_ref(), INPUT_KEY) {
                    ElicitationAction::Accept => Asked::Yes,
                    _ => Asked::No { shown: true },
                };
            }
        }
        let Ok(id) = elicit::new_id() else {
            return Asked::No { shown: false };
        };
        let params = ElicitRequestParams::FormElicitationParams {
            meta: None,
            message,
            requested_schema: ElicitationSchema::new(BTreeMap::new()),
        };
        let state = format!("{REQUEST_STATE_PREFIX}{id}");
        match elicit::show(ask.context, INPUT_KEY, state, params).await {
            Shown::Pending(response) => {
                tier.support_questions
                    .insert(id, &binding.subject, binding.clone());
                Asked::Pending(response)
            }
            Shown::Answered(ElicitationAction::Accept) => Asked::Yes,
            Shown::Answered(_) => Asked::No { shown: true },
            Shown::Failed => Asked::No { shown: false },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bussard_service::support::{KnownProblem, Support, UnsupportedReason};

    fn known_problem() -> support::SupportView {
        Support::Unsupported {
            application_id: Some("0004B00C01".to_string()),
            application: Some("M-0004_A-B00C-01".to_string()),
            name: None,
            reason: UnsupportedReason::KnownProblem,
            known: Some(Box::new(KnownProblem {
                problem: "differs from ETS in the sweep, #1060".to_string(),
                cause: Some("capture unusable".to_string()),
            })),
        }
        .view()
    }

    #[test]
    fn test_next_step_renders_the_cause_of_a_known_problem() {
        assert_eq!(
            next_step("1.1.9", &known_problem(), Via::Flag),
            "Tell the human that 1.1.9 has a known problem on bussard's device-support list \
             (differs from ETS in the sweep, #1060: capture unusable), and that a wrong image \
             can leave the device not working; say the cause as it stands. Recommend a backup \
             first and ETS as the safe way. Only if the human explicitly says to write anyway, \
             call the same tool again with the same plan_digest and allow_unsupported: true. \
             Never decide this for them."
        );
        assert_eq!(
            next_step("1.1.9", &known_problem(), Via::Asked { shown: true }),
            "The human said no to bussard's own question about writing 1.1.9: 1.1.9 has a known \
             problem on bussard's device-support list (differs from ETS in the sweep, #1060: \
             capture unusable). Do not write it; recommend ETS for this device. Call the tool \
             again only if the human asks to, and bussard asks them again."
        );
    }

    #[test]
    fn test_question_names_the_known_problem_and_its_cause()
    -> Result<(), Box<dyn std::error::Error>> {
        let verdict = Support::Unsupported {
            application_id: Some("0004B00C01".to_string()),
            application: Some("M-0004_A-B00C-01".to_string()),
            name: None,
            reason: UnsupportedReason::KnownProblem,
            known: Some(Box::new(KnownProblem {
                problem: "differs from ETS in the sweep, #1060".to_string(),
                cause: Some("capture unusable".to_string()),
            })),
        };
        let refused = Refused(SupportRefusal {
            target: "1.1.9".parse()?,
            verdict,
        });
        assert_eq!(
            refused.question(),
            "1.1.9 runs M-0004_A-B00C-01, which has a known problem (differs from ETS in the \
             sweep, #1060: capture unusable). Writing it anyway can leave the device not working. \
             Back the device up first; ETS is the safe way to program it. Write anyway?"
        );
        Ok(())
    }

    #[test]
    fn test_decide_supported_goes_without_the_override() {
        for (asks, flag) in [(false, false), (false, true), (true, false), (true, true)] {
            assert_eq!(decide(asks, flag, false, false), Step::Go(false));
        }
    }

    #[test]
    fn test_decide_a_plan_that_did_not_report_it_is_plan_again() {
        // The flag cannot help when the plan did not report the device
        // unsupported, on either client.
        assert_eq!(decide(false, true, true, true), Step::Refuse(Via::Replan));
        assert_eq!(decide(false, false, true, true), Step::Refuse(Via::Replan));
        assert_eq!(decide(true, true, true, true), Step::Refuse(Via::Replan));
    }

    #[test]
    fn test_decide_asks_the_human_whatever_the_flag() {
        assert_eq!(decide(true, true, true, false), Step::Ask);
        assert_eq!(decide(true, false, true, false), Step::Ask);
    }

    #[test]
    fn test_decide_without_elicitation_the_flag_decides() {
        assert_eq!(decide(false, true, true, false), Step::Go(true));
        assert_eq!(decide(false, false, true, false), Step::Refuse(Via::Flag));
    }
}
