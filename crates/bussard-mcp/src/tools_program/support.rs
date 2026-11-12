//! The supported-device gate over MCP (issue #1089): every device write tool
//! asks [`bussard_service::support::authorize`], the function the CLI asks.
//!
//! The override (`allow_unsupported: true`) counts only with the digest of a
//! plan that reported the device unsupported, so the assistant has seen the
//! warning and put it to the human; it is the trust model of every other
//! confirmed write (#905). A refusal is a normal result with the code
//! `unsupported_device`; nothing is written and the digest stays valid.

use bussard_model::{IndividualAddress, Model};
use bussard_service::report::Refusal;
use bussard_service::support::{self, SupportGrant, SupportRefusal};
use bussard_service::transport::ConnectionConfig;
use serde_json::{Value, json};

/// The refusal code of a write to a device not on the supported list.
pub(crate) const UNSUPPORTED_DEVICE: &str = "unsupported_device";

/// Why a write did not pass the support gate.
pub(crate) enum Refused {
    /// The device is not on the list and the override was not given (or
    /// not with a plan that reported it).
    Unsupported(SupportRefusal),
}

/// The support gate of a write of `target`: `allow_unsupported` counts only
/// when `plan_reported_unsupported`, the plan the digest names said so.
pub(crate) fn gate(
    connection: &ConnectionConfig,
    model: &Model,
    target: IndividualAddress,
    allow_unsupported: bool,
    plan_reported_unsupported: bool,
) -> Result<SupportGrant, Refused> {
    support::authorize(
        connection,
        target,
        support::verdict_at(Some(model), target),
        allow_unsupported && plan_reported_unsupported,
    )
    .map_err(Refused::Unsupported)
}

impl Refused {
    /// The refusal as one sentence, for a pre-flight that answers with a
    /// reason string.
    pub(crate) fn reason(&self) -> String {
        match self {
            Refused::Unsupported(refusal) => format!(
                "{UNSUPPORTED_DEVICE}: {}. Nothing was written. To write anyway, the human must \
                 say so explicitly; then call again with allow_unsupported: true and the \
                 plan_digest of a plan that reported the device unsupported.",
                refusal.sentence()
            ),
        }
    }

    /// The structured refusal: `ok: false`, `refused: true`, `code:
    /// unsupported_device`, the `support` verdict, the `override` and the
    /// homeowner's summary.
    pub(crate) fn answer(&self, model: &Model, digest_kept: bool) -> Value {
        let Refused::Unsupported(refusal) = self;
        let target = refusal.target.to_string();
        let reason = format!(
            "{}. Nothing was written.{}",
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
        crate::reply::merge(
            &mut out,
            json!({
                "code": UNSUPPORTED_DEVICE,
                "support": refusal.verdict.view(),
                "override": "allow_unsupported: true",
                "next_step": format!(
                    "Tell the human that {target} is not on bussard's list of supported devices: \
                     bussard has never checked what it writes to this product against ETS, and \
                     a wrong image can leave the device not working. Recommend a backup first \
                     and ETS as the safe way. Only if the human explicitly says to write anyway, \
                     call the same tool again with the same plan_digest and allow_unsupported: \
                     true. Never decide this for them."
                ),
            }),
        );
        out
    }
}
