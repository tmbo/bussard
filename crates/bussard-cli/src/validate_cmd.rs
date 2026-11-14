//! The `bussard validate` subcommand.
//!
//! Loads the model and prints diagnostics either as rustc-style coloured text
//! (the shared [`crate::style`], respecting `NO_COLOR`) or as a JSON array. Exits with a failure code if any
//! diagnostic is an error.
//!
//! The rules are the ones `knx_validate` runs, one function in the service
//! (issue #1112). Among them the configured keyring (issue
//! #205, [`bussard_model::validate_keyring`]): the keyring `BUSSARD_KEYRING`
//! or `connection.keyring` names is decrypted at most once, with the password
//! from `BUSSARD_KEYRING_PASSWORD`; without it one info line says the key
//! checks were skipped. `validate` stays offline and never prompts.

use std::path::Path;
use std::process::ExitCode;

use bussard_model::{Diagnostic, Model, Severity, validate_in_dir};
use bussard_service::validate_report::{
    ValidateFilter, ValidateReport, ValidateRun, validate_project,
};

use crate::cli::{Resolved, Run, Spec};
use crate::style::{Style, Tone, count};

/// `bussard validate`.
#[derive(Debug, clap::Args)]
pub(crate) struct ValidateArgs {}

impl Run for ValidateArgs {
    fn spec(&self) -> Spec {
        Spec::FILES.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(g.dir(), g.json)
    }
}

/// Runs the validate command over the model in `dir`: the rule set
/// `knx_validate` runs ([`validate_project`], issue #1112).
fn run(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let model = Model::load(dir)?;
    let run = validate_project(&model, dir, keyring_facts(dir).as_ref());
    let has_errors = bussard_model::has_errors(&run.diagnostics);

    if json {
        print_json(run);
    } else {
        print_text(&run.diagnostics);
    }

    Ok(if has_errors {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// The keyring `BUSSARD_KEYRING` or `connection.keyring` names (the bus
/// commands' resolver without a `--keyring` flag), decrypted at most once.
fn keyring_facts(dir: &Path) -> Option<bussard_model::KeyringFacts> {
    let env = crate::conn_cmd::EnvGlobals::from_process();
    bussard_service::secure::keyring_file(dir, None, env.keyring.as_deref()).map(|resolved| {
        bussard_service::secure::keyring_facts(&resolved.path, resolved.source.describe())
    })
}

/// Prints diagnostics in rustc style.
fn print_text(diagnostics: &[Diagnostic]) {
    print!("{}", render_text(diagnostics, Style::stdout()));
}

/// Diagnostics in rustc style, coloured by severity, then one summary line.
fn render_text(diagnostics: &[Diagnostic], style: Style) -> String {
    let mut out = String::new();
    for d in diagnostics {
        let (label, tone) = match d.severity {
            Severity::Error => ("error", Tone::Error),
            Severity::Warning => ("warning", Tone::Warn),
            Severity::Info => ("info", Tone::Dim),
        };
        let header = style.paint(&style.bold(&format!("{label}[{}]", d.code)), tone);
        out.push_str(&format!("{header}: {}\n", d.message));
        out.push_str(&format!("  {} {}\n", style.dim("-->"), d.location));
    }
    let (errors, warnings) = counts(diagnostics);
    if diagnostics.is_empty() {
        out.push_str(&style.summary(&[("No problems found".to_string(), Tone::Ok)]));
        out.push('\n');
        return out;
    }
    let tone = |n: usize, bad: Tone| if n > 0 { bad } else { Tone::Ok };
    out.push('\n');
    out.push_str(&style.summary(&[
        (count(errors, "error", "errors"), tone(errors, Tone::Error)),
        (
            count(warnings, "warning", "warnings"),
            tone(warnings, Tone::Warn),
        ),
    ]));
    out.push('\n');
    out
}

/// Prints the run as the JSON document `knx_validate` returns.
fn print_json(run: ValidateRun) {
    let report = ValidateReport::new(run, &ValidateFilter::all());
    if let Err(e) = crate::output::report(&report) {
        eprintln!("error: failed to serialize diagnostics: {e}");
    }
}

/// Counts `(errors, warnings)` in a diagnostic list.
fn counts(diagnostics: &[Diagnostic]) -> (usize, usize) {
    let count = |s: Severity| diagnostics.iter().filter(|d| d.severity == s).count();
    (count(Severity::Error), count(Severity::Warning))
}

/// The validation gate in front of a device write: prints every error (and the
/// warning count) and returns `false` when the model has errors, so the caller
/// stops before the bus is touched.
pub(crate) fn gate(model: &Model, dir: &Path, verb: &str) -> bool {
    let diagnostics = validate_in_dir(model, dir);
    let (errors, warnings) = counts(&diagnostics);
    if errors == 0 {
        return true;
    }
    let style = Style::stderr();
    eprintln!(
        "{}",
        style.error_line(&format!(
            "refusing to {verb}: your project has {} ({}); nothing was written. Fix these \
             first:",
            count(errors, "error", "errors"),
            count(warnings, "warning", "warnings")
        ))
    );
    for d in diagnostics.iter().filter(|d| d.severity == Severity::Error) {
        eprintln!(
            "  {}: {}",
            style.paint(&format!("error[{}]", d.code), Tone::Error),
            d.message
        );
        eprintln!("    {} {}", style.dim("-->"), d.location);
    }
    eprintln!(
        "{}",
        style.dim("Run `bussard validate` to see every problem.")
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(severity: Severity, code: &'static str) -> Diagnostic {
        Diagnostic::new(code, severity, "devices/1.1.4.toml", "the message")
    }

    #[test]
    fn test_render_text_plain_counts_and_points() {
        let text = render_text(
            &[
                diag(Severity::Error, "E001"),
                diag(Severity::Warning, "W002"),
                diag(Severity::Warning, "W003"),
            ],
            Style::plain(),
        );
        assert_eq!(
            text,
            "error[E001]: the message\n  --> devices/1.1.4.toml\n\
             warning[W002]: the message\n  --> devices/1.1.4.toml\n\
             warning[W003]: the message\n  --> devices/1.1.4.toml\n\
             \n1 error, 2 warnings\n"
        );
    }

    #[test]
    fn test_render_text_clean_project() {
        assert_eq!(render_text(&[], Style::plain()), "No problems found\n");
    }

    #[test]
    fn test_render_text_colour_by_severity() {
        let text = render_text(&[diag(Severity::Error, "E001")], Style::rich());
        assert!(text.contains("\u{1b}[31m"), "{text:?}");
        assert!(text.contains("\u{1b}[32m"), "0 warnings in green: {text:?}");
    }
}
