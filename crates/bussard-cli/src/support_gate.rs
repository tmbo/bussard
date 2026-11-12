//! The supported-device gate at the terminal (issue #1089): every gated
//! command asks [`bussard_service::support::authorize`], the function the MCP
//! server asks, and says what it decided.

use bussard_model::IndividualAddress;
use bussard_model::schema::Device;
use bussard_service::support::{self, SupportGrant, SupportStatus};
use bussard_service::transport::ConnectionConfig;

/// The grant for writing `device` at `target` on `config`, judged on
/// `application`, the program the write builds from (`None` without
/// product data), or the refusal of an unsupported device on a non-loopback
/// gateway without `--allow-unsupported`. `given` is the grant an outer
/// command (`replace`, `commission`) already made: it is reused for the same
/// verdict, so the operator is asked and told once. A forced write is said
/// on stderr; a loopback gateway passes silently (`plan`, `describe` and
/// `device` show the verdict).
pub(crate) fn authorize(
    config: &ConnectionConfig,
    target: IndividualAddress,
    (device, application): (Option<&Device>, Option<&str>),
    allow_unsupported: bool,
    given: Option<&SupportGrant>,
) -> anyhow::Result<SupportGrant> {
    if let Some(grant) = given {
        return grant
            .reuse_for(target, device, application)
            .map_err(anyhow::Error::msg);
    }
    let grant = support::authorize(config, target, device, application, allow_unsupported)?;
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
