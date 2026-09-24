//! The y/N confirmation every bus-writing command asks before it acts.
//!
//! Before issue #86 each command carried its own copy of the same twenty
//! lines. The rule they all implement: `--yes` skips the prompt; a non-TTY
//! without `--yes` is refused, because a scripted write must opt in explicitly
//! rather than fire blind at whatever gateway `bussard.yaml` names (issue #74);
//! on a TTY the question goes to stderr and only `y`/`yes` proceeds.

use std::io::{IsTerminal, Write};

use anyhow::{Context, bail};

/// Asks `prompt` (the text before ` [y/N] `) on stderr and reads the answer.
///
/// Returns `Ok(true)` without asking when `yes` is set. Without a terminal on
/// stdin and without `yes`, fails with `refusal`, which should name the action
/// and say which flag makes it non-interactive.
pub fn confirm(yes: bool, prompt: &str, refusal: impl FnOnce() -> String) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!("{}", refusal());
    }
    ask(prompt)
}

/// Asks `prompt` on stderr unconditionally and reads a y/N answer from stdin.
///
/// For callers that already decided a prompt is appropriate (e.g. `adopt`,
/// which gates its non-interactive path separately).
pub fn ask(prompt: &str) -> anyhow::Result<bool> {
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(is_yes(&line))
}

/// Whether an answer line means yes.
fn is_yes(line: &str) -> bool {
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_yes_accepts_only_yes_forms() {
        for yes in ["y", "Y", "yes", "Yes", " y\n"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["", "n", "N", "no", "YES!", "sure"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }

    #[test]
    fn test_confirm_yes_skips_the_prompt() -> anyhow::Result<()> {
        assert!(confirm(true, "unused", || "unused".to_string())?);
        Ok(())
    }
}
