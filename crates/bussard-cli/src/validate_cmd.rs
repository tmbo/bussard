//! The `bussard validate` subcommand.
//!
//! Loads the model and prints diagnostics either as rustc-style coloured text
//! (the shared [`crate::style`], respecting `NO_COLOR`) or as a JSON array. Exits with a failure code if any
//! diagnostic is an error.
//!
//! Besides the model's own rules it checks the configured keyring (issue
//! #205, [`bussard_model::validate_keyring`]): the keyring `BUSSARD_KEYRING`
//! or `connection.keyring` names is decrypted at most once, with the password
//! from `BUSSARD_KEYRING_PASSWORD`; without it one info line says the key
//! checks were skipped. `validate` stays offline and never prompts.

use std::path::Path;
use std::process::ExitCode;

use bussard_model::{Diagnostic, Model, Severity, validate_in_dir};

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

/// Runs the validate command over the model in `dir`.
fn run(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let model = Model::load(dir)?;
    let mut diagnostics = validate_in_dir(&model, dir);
    diagnostics.extend(keyring_diagnostics(&model, dir));
    diagnostics.sort_by(|a, b| a.location.cmp(&b.location).then(a.code.cmp(b.code)));

    if json {
        print_json(&diagnostics);
    } else {
        print_text(&diagnostics);
    }

    let has_errors = bussard_model::has_errors(&diagnostics);
    Ok(if has_errors {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// The keyring rules for the model in `dir`: the keyring `BUSSARD_KEYRING`
/// or `connection.keyring` names (the bus commands' resolver without a
/// `--keyring` flag), checked by [`bussard_model::validate_keyring`].
fn keyring_diagnostics(model: &Model, dir: &Path) -> Vec<Diagnostic> {
    let env = crate::conn_cmd::EnvGlobals::from_process();
    let facts =
        bussard_service::secure::keyring_file(dir, None, env.keyring.as_deref()).map(|resolved| {
            bussard_service::secure::keyring_facts(&resolved.path, resolved.source.describe())
        });
    let mut diags = bussard_model::validate_keyring(model, facts.as_ref());
    // W034 (issue #297): secured GAs only tunnel clients can write, on
    // devices that do not admit the tunnelling addresses.
    diags.extend(bussard_service::admission::tunnel_gap_diagnostics(
        model,
        facts.as_ref(),
    ));
    // W047 (issue #391): an IP interface's [knxnet] tunnels against the
    // tunnelling addresses the key store lists for it.
    diags.extend(
        bussard_service::admission::knxnet_tunnel_keyring_diagnostics(model, facts.as_ref()),
    );
    diags
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

/// Prints diagnostics as a JSON document: `{ "schema", "diagnostics": [...] }`.
fn print_json(diagnostics: &[Diagnostic]) {
    let items: Vec<serde_json::Value> = diagnostics
        .iter()
        .map(|d| {
            serde_json::json!({
                "code": d.code,
                "severity": d.severity.to_string(),
                "message": d.message,
                "location": d.location,
            })
        })
        .collect();
    let doc = serde_json::json!({ "diagnostics": items });
    match crate::output::render(crate::output::schema::VALIDATE, &doc) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("error: failed to serialize diagnostics: {e}"),
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
