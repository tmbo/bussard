//! The supported-device gate at the terminal (issue #1089): every gated
//! command asks [`bussard_service::support::authorize`], the function the MCP
//! server asks, and says what it decided.

use bussard_model::IndividualAddress;
use bussard_service::support::{self, Support, SupportGrant, SupportStatus};
use bussard_service::transport::ConnectionConfig;

/// The grant for writing `target` on `config`, or the refusal of an
/// unsupported device on a non-loopback gateway without
/// `--allow-unsupported`. A forced write is said on stderr; a loopback
/// gateway passes silently (`plan`, `describe` and `device` show the verdict).
pub(crate) fn authorize(
    config: &ConnectionConfig,
    target: IndividualAddress,
    verdict: Support,
    allow_unsupported: bool,
) -> anyhow::Result<SupportGrant> {
    let grant = support::authorize(config, target, verdict, allow_unsupported)?;
    if grant.forced()
        && let Some(line) = grant.plan_line()
    {
        eprintln!("{line}");
    }
    Ok(grant)
}

/// The history record's result for a write `grant` let through: `what`,
/// with `; support: forced` when the write was forced.
pub(crate) fn history_result(what: &str, grant: &SupportGrant) -> String {
    match grant.status() {
        SupportStatus::Forced => format!("{what}; support: forced"),
        _ => what.to_string(),
    }
}
