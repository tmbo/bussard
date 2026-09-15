//! The `bussard import` subcommand.
//!
//! Imports a `.knxproj` (or an `xknxproject` JSON dump) into the YAML model,
//! writing it to an output directory via the model's deterministic saver.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use bussard_model::Model;

/// Runs `bussard import` from a `.knxproj` file.
///
/// Password resolution order: the `--password` flag, then the
/// `BUSSARD_PROJECT_PASSWORD` environment variable, then an interactive prompt
/// (only when stdin is a TTY).
pub fn run_knxproj(
    path: &Path,
    out: &Path,
    password_flag: Option<String>,
) -> anyhow::Result<ExitCode> {
    let password = resolve_password(password_flag);

    let model = match bussard_project::import(path, password.as_deref()) {
        Ok(model) => model,
        Err(bussard_project::ImportError::PasswordRequired) => {
            // If we have no password yet and a TTY is available, prompt once.
            if password.is_none() && std::io::stdin().is_terminal() {
                let pw = prompt_password()?;
                bussard_project::import(path, Some(&pw))?
            } else {
                anyhow::bail!(
                    "project is password-protected; provide --password, set \
                     BUSSARD_PROJECT_PASSWORD, or run in a terminal to be prompted"
                );
            }
        }
        Err(e) => return Err(e.into()),
    };

    write_model(&model, out)
}

/// Runs `bussard import --from-json`.
pub fn run_json(path: &Path, out: &Path) -> anyhow::Result<ExitCode> {
    let model = bussard_project::import_from_json(path)?;
    write_model(&model, out)
}

/// Writes the model and prints a short summary.
fn write_model(model: &Model, out: &Path) -> anyhow::Result<ExitCode> {
    model.save(out)?;
    println!(
        "imported {} group addresses, {} devices, {} link entries → {}",
        model.groups.groups.len(),
        model.devices.len(),
        model.links.links.values().map(Vec::len).sum::<usize>(),
        out.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// Resolves the password from the flag or the environment (no prompt here).
fn resolve_password(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("BUSSARD_PROJECT_PASSWORD").ok())
        .filter(|s| !s.is_empty())
}

/// Prompts for the project password on the terminal.
fn prompt_password() -> anyhow::Result<String> {
    let pw = rpassword::prompt_password("Project password: ")?;
    Ok(pw)
}
