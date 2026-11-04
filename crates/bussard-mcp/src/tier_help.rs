//! The `bussard mcp --help` texts of the tier flags, built from the
//! registration tables ([`crate::tool_names_with_ha`] and the tier lists) so
//! the tool names and counts they print cannot drift from the server
//! (issue #704).

use crate::{tool_names_with_ha, tools_enroll, tools_ha, tools_model, tools_program};

/// How many tools each tier registers, from [`crate::tool_names_with_ha`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierCounts {
    /// Tools in `--passive` mode, model edits included.
    pub passive: usize,
    /// Tools in the default (read) tier, model edits included.
    pub default: usize,
    /// Tools with `--allow-writes`, model edits included.
    pub writes: usize,
    /// Tools `--no-model-edits` removes from any tier (the model edits and
    /// the certificate enrolment).
    pub model_edits: usize,
    /// Tools `--allow-programming` adds to any non-passive tier.
    pub programming: usize,
    /// Tools the Home Assistant tier adds to any tier.
    pub home_assistant: usize,
}

/// The tool counts of every tier, computed from the registration tables.
pub fn tier_counts() -> TierCounts {
    TierCounts {
        passive: names(true, false, false, false, false).len(),
        default: names(false, false, false, false, false).len(),
        writes: names(false, true, false, false, false).len(),
        model_edits: no_model_edits_omitted().len(),
        programming: tools_program::PROGRAMMING_TOOLS.len(),
        home_assistant: tools_ha::HA_TOOLS.len(),
    }
}

/// The tools the default tier has and `--passive` omits.
pub fn passive_omitted() -> Vec<&'static str> {
    added(
        &names(true, false, false, false, false),
        &names(false, false, false, false, false),
    )
}

/// The tools `--allow-writes` adds to the default tier.
pub fn writes_added() -> Vec<&'static str> {
    added(
        &names(false, false, false, false, false),
        &names(false, true, false, false, false),
    )
}

/// The tools `--no-model-edits` withholds: the model edits and the
/// certificate enrolment, which writes the key store.
pub fn no_model_edits_omitted() -> Vec<&'static str> {
    tools_model::MODEL_EDIT_TOOLS
        .iter()
        .chain(&tools_enroll::ENROLL_TOOLS)
        .copied()
        .collect()
}

/// Help for `--passive`.
pub fn passive_help() -> String {
    format!(
        "Passive mode: never transmit on the bus (omits {}). The server only observes.",
        code_list(&passive_omitted())
    )
}

/// Help for `--allow-writes`.
pub fn allow_writes_help() -> String {
    format!(
        "Allow bus writes: registers {}. Off by default. Mutually exclusive with `--passive`.",
        code_list(&writes_added())
    )
}

/// Help for `--allow-programming`.
pub fn allow_programming_help() -> String {
    format!(
        "Programming tier: registers {}, which write one device after a plan the human \
         approved. Off by default. Mutually exclusive with `--passive`; a non-loopback \
         gateway also needs `--allow-remote-gateway` or BUSSARD_ALLOW_REAL_GATEWAY=1.",
        code_list(&tools_program::PROGRAMMING_TOOLS)
    )
}

/// Help for `--no-model-edits`.
pub fn no_model_edits_help() -> String {
    format!(
        "Refuse model edits: omits {}. The read tools stay available. Model edits only touch \
         the model files and the key store (never the bus), so they are on by default.",
        code_list(&no_model_edits_omitted())
    )
}

/// Help for `--allow-home-assistant`.
pub fn allow_home_assistant_help() -> String {
    format!(
        "Home Assistant tier: registers {} when bussard.toml has a `[home_assistant]` table. \
         Writes only the KNX YAML file it names and bussard's own automations, each after a \
         plan the human approved, then reloads them. Off by default; never touches the bus.",
        code_list(&tools_ha::HA_TOOLS)
    )
}

/// The tool counts per tier, printed after the `bussard mcp` options.
pub fn tier_counts_help() -> String {
    let c = tier_counts();
    format!(
        "Tools: {} with --passive, {} by default, {} with --allow-writes. --no-model-edits \
         removes {}, --allow-programming adds {} to any tier but --passive, and \
         --allow-home-assistant adds {}. On a missing or empty --dir the server starts with \
         {} only and registers its tier's tools once `knx_setup` has written the model.",
        c.passive,
        c.default,
        c.writes,
        c.model_edits,
        c.programming,
        c.home_assistant,
        code_list(&crate::onboarding::ONBOARDING_TOOLS)
    )
}

/// [`tool_names_with_ha`] with every switch spelled out.
fn names(
    passive: bool,
    allow_writes: bool,
    no_model_edits: bool,
    allow_programming: bool,
    home_assistant: bool,
) -> Vec<&'static str> {
    tool_names_with_ha(
        passive,
        allow_writes,
        no_model_edits,
        allow_programming,
        home_assistant,
    )
}

/// The names in `with` that `base` lacks, in `with`'s order.
fn added(base: &[&'static str], with: &[&'static str]) -> Vec<&'static str> {
    with.iter()
        .filter(|name| !base.contains(name))
        .copied()
        .collect()
}

/// `` `a`, `b` and `c` ``.
fn code_list(names: &[&str]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_list_joins_with_and() {
        assert_eq!(code_list(&[]), "");
        assert_eq!(code_list(&["a"]), "`a`");
        assert_eq!(code_list(&["a", "b", "c"]), "`a`, `b` and `c`");
    }

    #[test]
    fn test_tier_counts_add_up() {
        let c = tier_counts();
        assert_eq!(c.default, c.passive + passive_omitted().len());
        assert_eq!(c.writes, c.default + writes_added().len());
        assert!(writes_added().contains(&"knx_write_group"));
        assert!(passive_omitted().contains(&"knx_read_group"));
    }

    #[test]
    fn test_tier_counts_include_knx_viz_in_every_tier() {
        for (passive, writes) in [(true, false), (false, false), (false, true)] {
            assert!(names(passive, writes, false, false, false).contains(&"knx_viz"));
            assert!(names(passive, writes, true, false, false).contains(&"knx_viz"));
        }
        assert!(!passive_omitted().contains(&"knx_viz"));
        assert!(!no_model_edits_omitted().contains(&"knx_viz"));
    }

    #[test]
    fn test_tier_counts_help_names_the_onboarding_tools() {
        let help = tier_counts_help();
        assert!(
            help.contains("`knx_setup` and `knx_bus_status` only"),
            "{help}"
        );
    }

    #[test]
    fn test_allow_programming_help_names_every_programming_tool() {
        let help = allow_programming_help();
        for name in tools_program::PROGRAMMING_TOOLS {
            assert!(help.contains(&format!("`{name}`")), "{name}");
        }
        assert!(!help.contains("issue"));
    }
}
