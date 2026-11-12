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
//! written and the digest stays valid. [`BussardMcp::unsupported_override`]
//! is the one helper `knx_apply_device`, `knx_restore_parameters`,
//! `knx_restore_tables` and `knx_replace_device` decide through.

use std::collections::BTreeMap;

use bussard_model::{IndividualAddress, Model};
use bussard_service::report::Refusal;
use bussard_service::support::{self, SupportGrant, SupportRefusal};
use bussard_service::transport::ConnectionConfig;
use rmcp::RoleServer;
use rmcp::model::{
    CallToolResponse, CallToolResult, ElicitRequestParams, ElicitationAction, ElicitationSchema,
    InputResponses,
};
use rmcp::service::RequestContext;
use serde_json::{Value, json};

use crate::elicit::{self, Shown};
use crate::server::BussardMcp;

/// The refusal code of a write to a device not on the supported list.
pub(crate) const UNSUPPORTED_DEVICE: &str = "unsupported_device";

/// The key of the question in a multi round-trip call's `inputRequests`.
const INPUT_KEY: &str = "unsupported_device";

/// The prefix of the request state that names a pending question.
const REQUEST_STATE_PREFIX: &str = "bussard-unsupported:";

/// A write the support gate refused: the device is not on the list and the
/// override was not given (or not with a plan that reported it).
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
    /// The refusal as one sentence, for a pre-flight that answers with a
    /// reason string.
    pub(crate) fn reason(&self) -> String {
        format!(
            "{UNSUPPORTED_DEVICE}: {}. Nothing was written. To write anyway, the human must say \
             so explicitly; then call again with allow_unsupported: true and the plan_digest of \
             a plan that reported the device unsupported.",
            self.0.sentence()
        )
    }

    /// The question bussard puts to the human.
    fn question(&self) -> String {
        format!(
            "{}. bussard has never checked what it writes to this product against ETS, and a \
             wrong image can leave the device not working. Back the device up first; ETS is the \
             safe way to program it. Write anyway?",
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
        let next_step = match via {
            Via::Flag => format!(
                "Tell the human that {target} is not on bussard's list of supported devices: \
                 bussard has never checked what it writes to this product against ETS, and a \
                 wrong image can leave the device not working. Recommend a backup first and ETS \
                 as the safe way. Only if the human explicitly says to write anyway, call the \
                 same tool again with the same plan_digest and allow_unsupported: true. Never \
                 decide this for them."
            ),
            Via::Asked { shown: true } => format!(
                "The human said no to bussard's own question about writing {target}, which is \
                 not on bussard's list of supported devices. Do not write it; recommend ETS for \
                 this device. Call the tool again only if the human asks to, and bussard asks \
                 them again."
            ),
            Via::Asked { shown: false } => format!(
                "{target} is not on bussard's list of supported devices, and this chat app did \
                 not show bussard's question to the human. Nothing was written. Call the tool \
                 again only if the human asks to; bussard asks them again."
            ),
            Via::Replan => format!(
                "{target} is not on bussard's list of supported devices, and the plan this \
                 plan_digest names did not report that. Plan again, show the new plan and its \
                 support verdict to the human, and only then call the write again."
            ),
        };
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

/// What a write call carries for the human's answer to bussard's question:
/// the call's context and, in the second round of a multi round-trip call,
/// its request state and input responses.
pub(crate) struct Ask<'a> {
    /// The call's context: the client's capabilities and protocol.
    pub(crate) context: &'a RequestContext<RoleServer>,
    /// The request state of the second round, when this is one.
    pub(crate) request_state: Option<String>,
    /// The human's answers in the second round.
    pub(crate) responses: Option<InputResponses>,
}

impl Ask<'_> {
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

/// What bussard's question is bound to: the tool, its subject (a device, a
/// line, a job) and the plan digest. A second round answers only the
/// question it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    /// The tool.
    tool: &'static str,
    /// The device, line or job.
    subject: String,
    /// The plan digest the write presents.
    digest: String,
}

impl Binding {
    /// The question of `tool` about `subject`, for the write of `digest`.
    pub(crate) fn new(tool: &'static str, subject: impl ToString, digest: &str) -> Self {
        Binding {
            tool,
            subject: subject.to_string(),
            digest: digest.to_string(),
        }
    }
}

/// How a write goes on after the support gate.
pub(crate) enum Override {
    /// Write, with the override (`true`) or without.
    Go(bool),
    /// Answer the call with this: a refusal, or the question for the client.
    Answer(CallToolResponse),
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
    Override::Answer(CallToolResult::structured(value).into())
}

impl BussardMcp {
    /// The override of a device write (issue #1093). `check(allow)` is the
    /// write's support gate before its job ([`gate`]), `None` when it
    /// passes. Without elicitation `flag` (`allow_unsupported`) is the
    /// override and a refusal is answered as before; with it, bussard asks
    /// the human and `flag` does not count. A declined or dismissed question
    /// is a refusal with nothing written and the digest kept.
    pub(crate) async fn unsupported_override(
        &self,
        ask: &Ask<'_>,
        binding: Binding,
        flag: bool,
        check: impl Fn(bool) -> Option<Refused>,
    ) -> Override {
        let model = self.state().model.current();
        if !ask.asks_human() {
            return match check(flag) {
                None => Override::Go(flag),
                Some(refused) => respond(refused.answer(&model, true, Via::Flag)),
            };
        }
        let Some(refused) = check(false) else {
            return Override::Go(false);
        };
        if check(true).is_some() {
            return respond(refused.answer(&model, true, Via::Replan));
        }
        match self.ask_human(ask, &binding, refused.question()).await {
            Asked::Yes => Override::Go(true),
            Asked::No { shown } => respond(refused.answer(&model, true, Via::Asked { shown })),
            Asked::Pending(response) => Override::Answer(response),
        }
    }

    /// The override of a line write (issue #1093): `unsupported` is whether
    /// the line plan the digest names reported a device a write refuses as
    /// not on the list. Without elicitation `flag` is the override; with it
    /// bussard asks the human, and a no writes the supported devices only
    /// (each other one is reported as refused), as a write without the
    /// override does.
    pub(crate) async fn line_override(
        &self,
        ask: &Ask<'_>,
        binding: Binding,
        flag: bool,
        unsupported: bool,
    ) -> Override {
        if !ask.asks_human() {
            return Override::Go(flag);
        }
        if !unsupported {
            return Override::Go(false);
        }
        let question = format!(
            "Line {} has devices that are not on bussard's list of supported devices (the plan \
             names them). bussard has never checked what it writes to those products against \
             ETS, and a wrong image can leave a device not working. Back them up first; ETS is \
             the safe way to program them. Write them anyway? No writes the supported devices \
             only.",
            binding.subject
        );
        match self.ask_human(ask, &binding, question).await {
            Asked::Yes => Override::Go(true),
            Asked::No { .. } => Override::Go(false),
            Asked::Pending(response) => Override::Answer(response),
        }
    }

    /// Puts `message` to the human as a form-mode elicitation, by the
    /// transport of the call's protocol (see [`crate::elicit`]). The second
    /// round of a multi round-trip call answers the question its request
    /// state names, when that question was asked for `binding`; any other
    /// state is asked afresh.
    async fn ask_human(&self, ask: &Ask<'_>, binding: &Binding, message: String) -> Asked {
        let Ok(tier) = self.tier() else {
            return Asked::No { shown: false };
        };
        if let Some(id) = ask
            .request_state
            .as_deref()
            .and_then(|state| state.strip_prefix(REQUEST_STATE_PREFIX))
            && let Some(asked) = tier.support_questions.get(id)
        {
            // One question, one answer.
            tier.support_questions.retire(id);
            if asked == *binding {
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
