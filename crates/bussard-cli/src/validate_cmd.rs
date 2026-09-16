//! The `bussard validate` subcommand.
//!
//! Loads the model and prints diagnostics either as rustc-style coloured text
//! (respecting `NO_COLOR`) or as a JSON array. Exits with a failure code if any
//! diagnostic is an error.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use bussard_model::{Diagnostic, Model, Severity, validate_in_dir};
use owo_colors::OwoColorize;

/// Runs the validate command over the model in `dir`.
pub fn run(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let model = Model::load(dir)?;
    let diagnostics = validate_in_dir(&model, dir);

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

/// Prints diagnostics as a JSON array.
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
    // Pretty-print for readability; the shape is a stable array of objects.
    match serde_json::to_string_pretty(&items) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("error: failed to serialize diagnostics: {e}"),
    }
}
