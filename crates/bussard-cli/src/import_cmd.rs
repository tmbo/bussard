//! The `bussard import` subcommand.
//!
//! Imports a `.knxproj` into the TOML model,
//! writing it to an output directory via the model's deterministic saver.
//!
//! A **re-import** into a directory that already holds a model does not clobber:
//! it refreshes the generated sections (com-object tables, links wiring,
//! parameters) from ETS truth while preserving hand-authored fields (names,
//! locations, DPTs, `protected:` flags), **reporting** any hand-authored field
//! the fresh import disagrees with rather than overwriting it. See
//! [`bussard_model::merge`].
//!
//! The one `.knxkeys` exported next to the project is merged into the key
//! store `bussard.keys` (issue #241, [`crate::keys_cmd::import_neighbour`]).

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bussard_model::Model;
use bussard_service::files::import::ImportOutcome;
use bussard_service::setup::{DownloadPrompt, SetupError};

use crate::cli::{Resolved, Run, Spec};
use crate::confirm::DownloadConsent;
use crate::console::Console;
use crate::import_bundle::ConflictChoice;

/// `bussard import`.
#[derive(Debug, clap::Args)]
pub(crate) struct ImportArgs {
    /// The `.knxproj` or `.bussard` file to import.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Project password (else `BUSSARD_PROJECT_PASSWORD`, else prompt).
    #[arg(long)]
    password: Option<String>,
    /// On a re-import, keep this project's value for every hand-edited
    /// conflict and exit 0.
    #[arg(long, conflicts_with_all = ["theirs", "interactive"])]
    mine: bool,
    /// On a re-import, take the incoming value for every hand-edited conflict.
    #[arg(long, conflicts_with = "interactive")]
    theirs: bool,
    /// On a re-import, ask per conflict (needs a terminal).
    #[arg(long)]
    interactive: bool,
    /// Download missing vendor product data without asking. Without a
    /// terminal and without this flag nothing is downloaded; the missing
    /// order numbers are listed.
    #[arg(long, conflicts_with = "no_download")]
    yes_download: bool,
    /// Do not look up or download missing product data; list it instead.
    #[arg(long)]
    no_download: bool,
    /// Skip the confirmation prompt: import into a non-empty directory
    /// that holds no project yet.
    #[arg(long)]
    yes: bool,
}

impl Run for ImportArgs {
    fn spec(&self) -> Spec {
        Spec::CREATES
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        let dir = g.dir();
        if !crate::init_cmd::confirm_target(dir, self.yes, crate::init_cmd::TargetVerb::Import)? {
            eprintln!("Not confirmed; nothing written.");
            return Ok(ExitCode::FAILURE);
        }
        let choice = ConflictChoice::from_flags(self.mine, self.theirs, self.interactive);
        let consent = DownloadConsent {
            yes_download: self.yes_download,
            no_download: self.no_download,
        };
        if bussard_model::bundle::is_bundle_path(&self.project) {
            crate::import_bundle::run_bundle(&self.project, dir, choice)
        } else {
            run_knxproj(&self.project, dir, self.password, choice, consent)
        }
    }
}

/// Exit code returned when a re-import left hand-authored conflicts un-applied.
/// Distinct from success (0) so scripts/CI can detect that a human must
/// reconcile the reported fields; the write still happened (hand edits intact).
pub(crate) const EXIT_CONFLICTS: u8 = 3;

/// Runs `bussard import` from a `.knxproj` file.
///
/// Password resolution order: the `--password` flag, then the
/// `BUSSARD_PROJECT_PASSWORD` environment variable, then an interactive prompt
/// (only when stdin is a TTY).
///
/// A re-import always refreshes the generated sections (com-object tables, link
/// wiring, parameters) from the project and always preserves hand-authored
/// fields, reporting any difference instead of overwriting it. There is no flag
/// for that: it is the only behaviour the merge implements.
fn run_knxproj(
    path: &Path,
    dir: &Path,
    password_flag: Option<String>,
    choice: ConflictChoice,
    consent: DownloadConsent,
) -> anyhow::Result<ExitCode> {
    let model = load_project(path, dir, password_flag)?;
    let code = write_model(model, dir, choice, "project", Some(consent), Some(path))?;
    crate::keys_cmd::import_neighbour(path, dir);
    Ok(code)
}

/// Loads the project at `path` for `dir`
/// ([`bussard_service::setup::import::load_project`]): the password from the
/// flag, then `BUSSARD_PROJECT_PASSWORD`, then a prompt when stdin is a
/// terminal.
pub(crate) fn load_project(
    path: &Path,
    dir: &Path,
    password_flag: Option<String>,
) -> anyhow::Result<Model> {
    Ok(bussard_service::setup::import::load_project(
        path,
        dir,
        password_flag,
        ask_password,
    )?)
}

/// The project password from a prompt, when stdin is a terminal.
pub(crate) fn ask_password() -> Result<Option<String>, SetupError> {
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    prompt_password().map(Some).map_err(SetupError::source)
}

/// Writes the freshly-imported `model` to `dir`
/// ([`bussard_service::files::import::write_model`]): a fresh import, or a
/// re-import that merges and reports every hand-edited conflict. Returns
/// [`EXIT_CONFLICTS`] when conflicts are left for a human.
///
/// `choice` settles hand-authored conflicts (see [`ConflictChoice`]); `source`
/// names the incoming side in sentences (`"project"` or `"bundle"`).
/// `fetch` runs the product-data download step for the devices' order
/// numbers ([`crate::confirm::DownloadConsent`]); `None` skips it. `project` is the ETS
/// export read, which `bussard.lock` pins as the devices' product source
/// until a vendor archive serves them (lock v2, issue #228).
pub(crate) fn write_model(
    model: Model,
    dir: &Path,
    choice: ConflictChoice,
    source: &str,
    fetch: Option<DownloadConsent>,
    project: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    let mut fetch = fetch;
    let prompt = fetch.as_mut().map(|c| c as &mut dyn DownloadPrompt);
    let outcome = bussard_service::files::import::write_model(
        model,
        dir,
        choice,
        source,
        prompt,
        project,
        &mut Console,
        &mut Console,
    )?;
    Ok(exit_code(&outcome))
}

/// The exit code of an import: [`EXIT_CONFLICTS`] when hand-edited conflicts
/// are left for a human (nobody chose `--mine`, `--theirs` or
/// `--interactive`), with the line that says how to settle them; the
/// sentences were already printed.
pub(crate) fn exit_code(outcome: &ImportOutcome) -> ExitCode {
    if !outcome.unresolved {
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "\nGenerated sections (com_objects, links wiring, parameters) were refreshed. \
         The {} hand-edited field(s) above were KEPT. Re-run with --theirs to take the \
         incoming values, --mine to keep these and exit 0, or --interactive to choose each.",
        outcome.kept
    );
    ExitCode::from(EXIT_CONFLICTS)
}

/// Prompts for the project password on the terminal.
fn prompt_password() -> anyhow::Result<String> {
    let pw = rpassword::prompt_password("Project password: ")?;
    Ok(pw)
}
