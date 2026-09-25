//! The `bussard validate` subcommand.
//!
//! Loads the model and prints diagnostics either as rustc-style coloured text
//! (respecting `NO_COLOR`) or as a JSON array. Exits with a failure code if any
//! diagnostic is an error.
//!
//! Besides the model's own rules it checks the configured keyring (issue
//! #205, [`bussard_model::validate_keyring`]): the keyring `BUSSARD_KEYRING`
//! or `connection.keyring` names is decrypted at most once, with the password
//! from `BUSSARD_KEYRING_PASSWORD`; without it one info line says the key
//! checks were skipped. `validate` stays offline and never prompts.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use bussard_model::{Diagnostic, Model, Severity, validate_in_dir};
use owo_colors::OwoColorize;

/// Runs the validate command over the model in `dir`.
pub fn run(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
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
        crate::conn_cmd::resolve_keyring(None, env.keyring.as_deref(), dir).map(|resolved| {
            bussard_service::secure::keyring_facts(&resolved.path, resolved.source.describe())
        });
    bussard_model::validate_keyring(model, facts.as_ref())
}

/// Whether colour should be used: enabled on a terminal unless `NO_COLOR` is set.
fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// Prints diagnostics in rustc style.
fn print_text(diagnostics: &[Diagnostic]) {
    let color = use_color();
    let mut errors = 0usize;
    let mut warnings = 0usize;

    for d in diagnostics {
        let label = match d.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        match d.severity {
            Severity::Error => errors += 1,
            Severity::Warning => warnings += 1,
            Severity::Info => {}
        }

        let header = format!("{label}[{}]", d.code);
        if color {
            let header = match d.severity {
                Severity::Error => header.red().bold().to_string(),
                Severity::Warning => header.yellow().bold().to_string(),
                Severity::Info => header.cyan().bold().to_string(),
            };
            println!("{header}: {}", d.message);
            println!("  {} {}", "-->".blue(), d.location);
        } else {
            println!("{header}: {}", d.message);
            println!("  --> {}", d.location);
        }
    }

    if diagnostics.is_empty() {
        let msg = "no problems found";
        if color {
            println!("{}", msg.green());
        } else {
            println!("{msg}");
        }
        return;
    }

    let summary = format!(
        "{} error{}, {} warning{}",
        errors,
        if errors == 1 { "" } else { "s" },
        warnings,
        if warnings == 1 { "" } else { "s" }
    );
    println!();
    if color {
        if errors > 0 {
            println!("{}", summary.red().bold());
        } else if warnings > 0 {
            println!("{}", summary.yellow().bold());
        } else {
            println!("{summary}");
        }
    } else {
        println!("{summary}");
    }
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

/// The one-line validation summary `import` prints after writing:
/// `validation: 0 error(s), 2 warning(s)`, followed by each error.
///
/// Errors never undo the import (the files are what the project says); they
/// are what the owner fixes next, so they are listed with their location.
pub(crate) fn print_summary(dir: &Path) {
    let model = match Model::load(dir) {
        Ok(model) => model,
        Err(err) => {
            println!("validation: the written model does not load: {err}");
            return;
        }
    };
    let diagnostics = validate_in_dir(&model, dir);
    let (errors, warnings) = counts(&diagnostics);
    println!("validation: {errors} error(s), {warnings} warning(s)");
    for d in diagnostics.iter().filter(|d| d.severity == Severity::Error) {
        println!("  error[{}]: {} ({})", d.code, d.message, d.location);
    }
    if errors + warnings > 0 {
        println!(
            "  run `bussard validate --dir {}` for the details",
            dir.display()
        );
    }
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
    eprintln!(
        "refusing to {verb}: the model has {errors} error(s) ({warnings} warning(s)); nothing \
         was written. Fix these first:"
    );
    for d in diagnostics.iter().filter(|d| d.severity == Severity::Error) {
        eprintln!("  error[{}]: {}", d.code, d.message);
        eprintln!("    --> {}", d.location);
    }
    false
}
