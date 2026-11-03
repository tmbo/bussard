//! Setting a model directory up from nothing: what `bussard init` and the MCP
//! tool `knx_setup` both run (issue #745).
//!
//! [`run`] resolves the gateway (given, routing, or found by KNXnet/IP
//! discovery), writes the TOML skeleton, and imports the ETS export given or
//! the one found next to the directory: product data from the export,
//! vendor downloads only with the caller's consent, the keyring next to the
//! project into the key store, and a validation summary. It never prints and
//! never asks: every line goes to an [`Output`], every question to a
//! [`SetupHooks`] method. The CLI answers them on the terminal; the MCP tool
//! answers them from its arguments and turns a question it cannot answer
//! into a question for the assistant.
//!
//! The pieces are public for the commands that share them: the product store
//! and the download step ([`products`]), the history snapshot and the fresh
//! import write ([`import`]), the skeleton files ([`skeleton`]) and the
//! gateway resolution ([`gateway`]).

pub mod gateway;
pub mod import;
pub mod products;
pub mod skeleton;

use std::path::{Path, PathBuf};

use bussard_model::Model;
use bussard_transport::knxnet::GatewayInfo;

pub use gateway::Resolution;
pub use skeleton::TargetState;

/// Where the lines of a setup step go. The CLI prints them (`say` on stdout,
/// `warn` on stderr, exactly as the commands always did); the MCP tool
/// collects them for its result.
pub trait Output {
    /// A line of normal output.
    fn say(&mut self, line: &str);
    /// A warning or error line.
    fn warn(&mut self, line: &str);
}

/// An [`Output`] that keeps every line, in order.
#[derive(Debug, Default, Clone)]
pub struct Collected {
    /// The lines said and warned, in order.
    pub lines: Vec<String>,
}

impl Output for Collected {
    fn say(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }

    fn warn(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
}

/// Why a setup step failed.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// A step failed; `context` says which, `source` why.
    #[error("{context}")]
    Failed {
        /// What was being done (`writing knx/bussard.toml`).
        context: String,
        /// The underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// An error passed through unchanged.
    #[error(transparent)]
    Source(Box<dyn std::error::Error + Send + Sync>),
    /// A refusal or failure stated in one sentence.
    #[error("{0}")]
    Message(String),
    /// The project is password-protected and no password was given.
    #[error(
        "project is password-protected; provide --password, set BUSSARD_PROJECT_PASSWORD, or \
         run in a terminal to be prompted"
    )]
    PasswordRequired,
}

impl SetupError {
    /// Wraps any error unchanged.
    pub fn source(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        SetupError::Source(err.into())
    }
}

/// `with_context` for [`SetupError`]: the context line over the cause.
pub(crate) trait Context<T> {
    /// Wraps the error with the context `f` returns.
    fn ctx(self, f: impl FnOnce() -> String) -> Result<T, SetupError>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> Context<T> for Result<T, E> {
    fn ctx(self, f: impl FnOnce() -> String) -> Result<T, SetupError> {
        self.map_err(|source| SetupError::Failed {
            context: f(),
            source: Box::new(source),
        })
    }
}

/// How the caller answers the product-data download question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadAnswer {
    /// Download.
    Yes,
    /// Do not download (declined).
    No,
    /// Not asked: nobody to ask. The line says how to consent; it is said
    /// and the files are not downloaded.
    Refused(String),
}

/// The product-data download question (the `import` and `adopt` download
/// step, and the import of a setup).
pub trait DownloadPrompt {
    /// Why downloads are skipped without asking (`--no-download`), or `None`
    /// to ask [`SetupHooks::download`].
    fn skip_downloads(&self) -> Option<String> {
        None
    }

    /// The one download question for the whole list of `files` archives.
    ///
    /// # Errors
    ///
    /// The answer could not be read.
    fn download(&mut self, question: &str, files: usize) -> Result<DownloadAnswer, SetupError>;
}

/// The questions a setup asks and the effects a surface supplies. Every
/// method has the answer of a caller that cannot ask: the MCP tool overrides
/// what its arguments settle, the CLI asks on the terminal.
pub trait SetupHooks: DownloadPrompt {
    /// The KNXnet/IP gateways discovery finds on the local network.
    ///
    /// # Errors
    ///
    /// Discovery could not run.
    fn discover(&mut self) -> Result<Vec<GatewayInfo>, SetupError> {
        gateway::real_discover()
    }

    /// The best-effort reachability check of a gateway that was given.
    fn probe(&mut self, endpoint: std::net::SocketAddrV4, out: &mut dyn Output) {
        gateway::probe_reachability(endpoint, out);
    }

    /// `dir` is not empty and holds no model: go on? `state` says what is
    /// there.
    ///
    /// # Errors
    ///
    /// The question could not be asked.
    fn confirm_target(&mut self, dir: &Path, state: TargetState) -> Result<bool, SetupError>;

    /// Discovery found no gateway: `true` writes a skeleton with a placeholder
    /// gateway, `false` stops before anything is written.
    fn no_gateway(&mut self, out: &mut dyn Output) -> bool;

    /// Several gateways answered: the index of the one to use, or `None` to
    /// stop before anything is written.
    ///
    /// # Errors
    ///
    /// The choice could not be read, or the caller refuses to choose.
    fn choose_gateway(
        &mut self,
        found: &[GatewayInfo],
        out: &mut dyn Output,
    ) -> Result<Option<usize>, SetupError>;

    /// Several ETS projects lie next to `dir` and none was named: `true`
    /// goes on without one, `false` stops before anything is written.
    fn several_projects(&mut self, dir: &Path, found: &[PathBuf], out: &mut dyn Output) -> bool;

    /// The project is password-protected and no password was given: the
    /// password to try once, or `None` to fail.
    ///
    /// # Errors
    ///
    /// The password could not be read.
    fn project_password(&mut self) -> Result<Option<String>, SetupError> {
        Ok(None)
    }

    /// Writes the freshly imported `model` into `dir` and returns the exit
    /// code of the import (0 on success). The default is the fresh import
    /// write [`import::write_fresh`]; the CLI merges into a model that is
    /// already there instead.
    ///
    /// # Errors
    ///
    /// The model could not be written.
    fn write_import(
        &mut self,
        model: Model,
        dir: &Path,
        project: Option<&Path>,
        out: &mut dyn Output,
    ) -> Result<u8, SetupError>
    where
        Self: Sized,
    {
        import::prepare_write(dir, out);
        import::write_fresh(model, dir, project, Some(self), out)?;
        Ok(0)
    }
}

/// What [`run`] is asked to do.
#[derive(Debug, Clone, Default)]
pub struct SetupRequest {
    /// The model directory to create.
    pub dir: PathBuf,
    /// A gateway `host[:port]`; `None` discovers one.
    pub gateway: Option<String>,
    /// Configure KNXnet/IP routing (multicast) instead of a tunnel.
    pub routing: bool,
    /// The project to import (`.knxproj`, or an xknxproject `.json` dump).
    pub project: Option<PathBuf>,
    /// Look for the one `.knxproj` next to `dir` when `project` is `None`.
    pub find_project: bool,
    /// The project password; `None` reads `BUSSARD_PROJECT_PASSWORD`.
    pub password: Option<String>,
}

/// How a [`run`] ended.
#[derive(Debug)]
pub enum SetupOutcome {
    /// `dir` already holds a model (`bussard.toml`); nothing was written.
    HasModel,
    /// The caller did not confirm a non-empty `dir`; nothing was written.
    NotConfirmed,
    /// A hook stopped the setup before anything was written (no gateway,
    /// several gateways, several projects).
    Stopped,
    /// The skeleton is written, and the project imported when there was one.
    Written {
        /// The transport written to `bussard.toml`.
        resolution: Resolution,
        /// The project imported, with the import's exit code.
        imported: Option<(PathBuf, u8)>,
    },
}

/// Sets `request.dir` up: the gateway, the skeleton and the import, asking
/// `hooks` every question and saying every line to `out`.
///
/// # Errors
///
/// A step failed: the gateway address does not resolve, the project does not
/// load (wrong or missing password, not an export), or a file cannot be
/// written. The project is loaded before the skeleton is written, so a
/// project that does not load leaves the directory as it was.
pub fn run<H: SetupHooks>(
    request: &SetupRequest,
    hooks: &mut H,
    out: &mut dyn Output,
) -> Result<SetupOutcome, SetupError> {
    let dir = request.dir.as_path();
    let mut project = request.project.clone();
    if project.is_none() && request.find_project {
        match skeleton::find_project(dir) {
            skeleton::ProjectSearch::None => {}
            skeleton::ProjectSearch::One(found) => {
                out.say(&format!(
                    "Found the ETS project {}; importing it.",
                    found.display()
                ));
                project = Some(found);
            }
            skeleton::ProjectSearch::Several(found) => {
                if !hooks.several_projects(dir, &found, out) {
                    return Ok(SetupOutcome::Stopped);
                }
            }
        }
    }

    // 1. Refuse a directory that already holds a model; ask before writing
    // into any other non-empty one.
    if dir.join(bussard_model::loader::CONFIG_FILE).is_file() {
        return Ok(SetupOutcome::HasModel);
    }
    let state = skeleton::target_state(dir)?;
    if state.needs_confirmation() && !hooks.confirm_target(dir, state)? {
        return Ok(SetupOutcome::NotConfirmed);
    }

    // 2. Resolve the gateway.
    let resolution =
        match gateway::resolve(request.gateway.as_deref(), request.routing, hooks, out)? {
            Some(resolution) => resolution,
            None => return Ok(SetupOutcome::Stopped),
        };

    // 3. Load the project before anything is written, so a wrong password
    // or a file that is not an export leaves the directory untouched.
    let loaded = match &project {
        Some(path) => Some(import::load_project(
            path,
            dir,
            request.password.clone(),
            || hooks.project_password(),
        )?),
        None => None,
    };

    // 4. Write the skeleton. With a project to import, `groups.toml` is the
    // import's to write, so the import is a fresh one, not a merge. A keyring
    // exported next to the project goes into the key store (the import does
    // it); only without the password is it recorded as `connection.keyring`.
    let keyring = project
        .as_deref()
        .filter(|_| !import::keyring_password_available())
        .and_then(skeleton::find_keyring)
        .map(|path| skeleton::keyring_setting(dir, &path));
    skeleton::write_skeleton(dir, &resolution, project.is_none(), keyring.as_deref(), out)?;
    if let Some(keyring) = &keyring {
        out.say(&format!(
            "Recorded the keyring as connection.keyring = {keyring:?} in {} (deprecated; \
             `bussard keys import` moves it into the key store).",
            dir.join("bussard.toml").display()
        ));
    }

    // 5. Import the project.
    let imported = match (project, loaded) {
        (Some(path), Some(model)) => {
            out.say("");
            out.say(&format!(
                "Importing {} into {}:",
                path.display(),
                dir.display()
            ));
            let is_json = is_json(&path);
            let code = hooks.write_import(model, dir, (!is_json).then_some(path.as_path()), out)?;
            import::import_neighbour(&path, dir, out);
            Some((path, code))
        }
        _ => None,
    };
    Ok(SetupOutcome::Written {
        resolution,
        imported,
    })
}

/// Whether `path` is an xknxproject `.json` dump rather than a `.knxproj`.
pub fn is_json(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Hooks that answer like a caller who cannot ask, never touching the
    /// network.
    #[derive(Default)]
    struct Quiet {
        confirmed: bool,
    }

    impl DownloadPrompt for Quiet {
        fn download(&mut self, _q: &str, _files: usize) -> Result<DownloadAnswer, SetupError> {
            Ok(DownloadAnswer::No)
        }
    }

    impl SetupHooks for Quiet {
        fn discover(&mut self) -> Result<Vec<GatewayInfo>, SetupError> {
            Ok(Vec::new())
        }

        fn probe(&mut self, _endpoint: std::net::SocketAddrV4, _out: &mut dyn Output) {}

        fn confirm_target(&mut self, _dir: &Path, _state: TargetState) -> Result<bool, SetupError> {
            Ok(self.confirmed)
        }

        fn no_gateway(&mut self, _out: &mut dyn Output) -> bool {
            false
        }

        fn choose_gateway(
            &mut self,
            _found: &[GatewayInfo],
            _out: &mut dyn Output,
        ) -> Result<Option<usize>, SetupError> {
            Ok(None)
        }

        fn several_projects(
            &mut self,
            _dir: &Path,
            _found: &[PathBuf],
            _out: &mut dyn Output,
        ) -> bool {
            false
        }
    }

    fn scratch(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("bussard-setup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn test_run_routing_writes_a_skeleton_that_loads() -> TestResult {
        let root = scratch("routing")?;
        let request = SetupRequest {
            dir: root.join("knx"),
            routing: true,
            ..SetupRequest::default()
        };
        let mut out = Collected::default();
        let outcome = run(&request, &mut Quiet::default(), &mut out)?;
        assert!(
            matches!(
                outcome,
                SetupOutcome::Written {
                    resolution: Resolution::Routing,
                    imported: None
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(
            out.lines,
            ["Configuring KNXnet/IP routing (multicast 224.0.23.12:3671)."]
        );
        let model = Model::load(&request.dir)?;
        assert!(model.groups.groups.is_empty());
        std::fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn test_run_no_gateway_stops_before_writing() -> TestResult {
        let root = scratch("nogw")?;
        let request = SetupRequest {
            dir: root.join("knx"),
            ..SetupRequest::default()
        };
        let outcome = run(&request, &mut Quiet::default(), &mut Collected::default())?;
        assert!(matches!(outcome, SetupOutcome::Stopped), "{outcome:?}");
        assert!(!request.dir.exists());
        std::fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn test_run_refuses_a_model_and_an_unconfirmed_directory() -> TestResult {
        let root = scratch("refuse")?;
        std::fs::write(root.join("notes.txt"), "mine")?;
        let request = SetupRequest {
            dir: root.clone(),
            routing: true,
            ..SetupRequest::default()
        };
        let outcome = run(&request, &mut Quiet::default(), &mut Collected::default())?;
        assert!(matches!(outcome, SetupOutcome::NotConfirmed), "{outcome:?}");
        std::fs::write(root.join("bussard.toml"), "# mine\n")?;
        let outcome = run(
            &request,
            &mut Quiet { confirmed: true },
            &mut Collected::default(),
        )?;
        assert!(matches!(outcome, SetupOutcome::HasModel), "{outcome:?}");
        assert_eq!(
            std::fs::read_to_string(root.join("bussard.toml"))?,
            "# mine\n"
        );
        std::fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn test_run_missing_project_fails_before_writing() -> TestResult {
        let root = scratch("noproject")?;
        let request = SetupRequest {
            dir: root.join("knx"),
            routing: true,
            project: Some(root.join("absent.knxproj")),
            ..SetupRequest::default()
        };
        let result = run(&request, &mut Quiet::default(), &mut Collected::default());
        assert!(result.is_err());
        assert!(!request.dir.exists(), "nothing written");
        std::fs::remove_dir_all(&root).ok();
        Ok(())
    }
}
