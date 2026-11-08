//! The `bussard mcp --help` texts of the tier flags, built from the
//! registration table ([`crate::TOOLS`]) so the tool names and counts they
//! print cannot drift from the server (issue #704).

use crate::{Tier, tool_names, tools_of};

/// How many tools each tier registers, from [`crate::TOOLS`].
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

/// The tool counts of every tier, computed from the registration table.
pub fn tier_counts() -> TierCounts {
    TierCounts {
        passive: tool_names(true, false, false).len(),
        default: tool_names(false, false, false).len(),
        writes: tool_names(false, true, false).len(),
        model_edits: no_model_edits_omitted().len(),
        programming: tools_of(Tier::Programming).len(),
        home_assistant: tools_of(Tier::HomeAssistant).len(),
    }
}

/// The tools the default tier has and `--passive` omits.
pub fn passive_omitted() -> Vec<&'static str> {
    tools_of(Tier::Bus)
}

/// The tools `--allow-writes` adds to the default tier.
pub fn writes_added() -> Vec<&'static str> {
    tools_of(Tier::Writes)
}

/// The tools `--no-model-edits` withholds: the model edits and the
/// certificate enrolment, which writes the key store.
pub fn no_model_edits_omitted() -> Vec<&'static str> {
    tools_of(Tier::ModelEdit)
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
        code_list(&tools_of(Tier::Programming))
    )
}

/// Help for `--no-model-edits`.
pub fn no_model_edits_help() -> String {
    format!(
        "Refuse project edits: omits {}. The read tools stay available. Project edits only touch \
         the project files and the key store (never the bus), so they are on by default.",
        code_list(&no_model_edits_omitted())
    )
}

/// Help for `--allow-home-assistant`.
pub fn allow_home_assistant_help() -> String {
    format!(
        "Home Assistant tier: registers {} when bussard.toml has a `[home_assistant]` table. \
         Writes only the KNX YAML file it names and bussard's own automations, each after a \
         plan the human approved, then reloads them. Off by default; never touches the bus.",
        code_list(&tools_of(Tier::HomeAssistant))
    )
}

/// The tool counts per tier, printed after the `bussard mcp` options.
pub fn tier_counts_help() -> String {
    let c = tier_counts();
    format!(
        "Tools: {} with --passive, {} by default, {} with --allow-writes. --no-model-edits \
         removes {}, --allow-programming adds {} to any tier but --passive, and \
         --allow-home-assistant adds {}. On a missing or empty --dir the server starts with \
         {} only and registers its tier's tools once `knx_setup` has written your project.",
        c.passive,
        c.default,
        c.writes,
        c.model_edits,
        c.programming,
        c.home_assistant,
        code_list(&crate::onboarding::ONBOARDING_TOOLS)
    )
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
            assert!(tool_names(passive, writes, false).contains(&"knx_viz"));
            assert!(tool_names(passive, writes, true).contains(&"knx_viz"));
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
        for name in tools_of(Tier::Programming) {
            assert!(help.contains(&format!("`{name}`")), "{name}");
        }
        assert!(!help.contains("issue"));
    }
}
