//! The confirmation rules every bus-writing command follows (issues #74, #86,
//! #228).
//!
//! One rule, one text:
//!
//! * `--yes` means exactly one thing: skip the confirmation prompt.
//! * Without a terminal on stdin and without `--yes`, a write command is
//!   refused with the one sentence [`refusal`] builds. A scripted write must
//!   opt in explicitly rather than fire blind at whatever gateway
//!   `bussard.toml` names; an explicit address or value is not itself
//!   consent. `assign`, `adopt`, `replace`, `commission` and `learn` refuse
//!   before they load the model ([`require_terminal_or_yes`], called from
//!   `main`); `flash`, `apply`, `restore`, `write` and `test` first read and
//!   show what they will change and refuse at their prompt ([`confirm`]).
//! * On a terminal the question goes to stderr and only `y`/`yes` proceeds.
//! * Consent to download vendor product data is a separate question with its
//!   own flag, [`DOWNLOAD_FLAG`]; `--yes` never answers it.

use std::io::{IsTerminal, Write};

use anyhow::{Context, bail};

/// The flag that consents to downloading vendor product data without asking
/// (`init`, `import`, `import-product`, `adopt`).
pub const DOWNLOAD_FLAG: &str = "--yes-download";

/// The one refusal for a write command run without a terminal and without
/// `--yes`. `action` names what was refused, e.g. `flash 1.1.4` or
/// `write 3/0/4 = on via 127.0.0.1:3671`.
pub fn refusal(action: &str) -> String {
    format!(
        "refusing to {action} without a terminal to confirm on; pass --yes to confirm \
         non-interactively"
    )
}

/// Refuses up front when there is neither `--yes` nor a terminal to ask on.
///
/// `main` calls this before the model loads for the commands whose first bus
/// action already acts, so a scripted run without consent fails fast with
/// [`refusal`].
///
/// # Errors
///
/// The [`refusal`] for `action` when `yes` is false and stdin is not a
/// terminal.
pub fn require_terminal_or_yes(yes: bool, action: &str) -> anyhow::Result<()> {
    if yes || std::io::stdin().is_terminal() {
        return Ok(());
    }
    bail!("{}", refusal(action))
}

/// Asks `prompt` (the text before ` [y/N] `) on stderr and reads the answer.
///
/// Returns `Ok(true)` without asking when `yes` is set. Without a terminal on
/// stdin and without `yes`, fails with the [`refusal`] for `action`.
///
/// # Errors
///
/// The refusal above, or a failure to read stdin.
pub fn confirm(yes: bool, prompt: &str, action: &str) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    require_terminal_or_yes(false, action)?;
    ask(prompt)
}

/// Asks `prompt` on stderr unconditionally and reads a y/N answer from stdin.
///
/// For a question that is not a write consent (`init`'s offer to scan).
///
/// # Errors
///
/// A failure to read stdin.
pub fn ask(prompt: &str) -> anyhow::Result<bool> {
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(is_yes(&line))
}

/// The answer to a download question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Download {
    /// Download: [`DOWNLOAD_FLAG`] was given, or the operator said yes.
    Yes,
    /// The operator said no on the terminal.
    No,
    /// No terminal to ask on and no [`DOWNLOAD_FLAG`].
    NoTerminal,
}

/// Asks the download question `question` unless [`DOWNLOAD_FLAG`]
/// (`yes_download`) already answered it.
///
/// # Errors
///
/// A failure to read stdin.
pub fn download(yes_download: bool, question: &str) -> anyhow::Result<Download> {
    if yes_download {
        return Ok(Download::Yes);
    }
    if !std::io::stdin().is_terminal() {
        return Ok(Download::NoTerminal);
    }
    Ok(if ask(question)? {
        Download::Yes
    } else {
        Download::No
    })
}

/// The one sentence for a download that had no terminal to ask on.
pub fn download_refusal(what: &str) -> String {
    format!(
        "refusing to download {what} without a terminal to confirm on; pass {DOWNLOAD_FLAG} to \
         consent non-interactively (--no-download to skip)"
    )
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
        assert!(confirm(true, "unused", "unused")?);
        Ok(())
    }

    #[test]
    fn test_refusal_names_the_action_and_the_flag() {
        assert_eq!(
            refusal("flash 1.1.4"),
            "refusing to flash 1.1.4 without a terminal to confirm on; pass --yes to confirm \
             non-interactively"
        );
    }

    #[test]
    fn test_download_flag_skips_the_question() -> anyhow::Result<()> {
        assert_eq!(download(true, "unused")?, Download::Yes);
        Ok(())
    }

    #[test]
    fn test_download_refusal_names_the_download_flag() {
        let text = download_refusal("the product data");
        assert!(text.contains(DOWNLOAD_FLAG), "{text}");
        assert!(!text.contains("--yes "), "{text}");
    }
}
