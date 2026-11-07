//! Setting a model directory up from nothing: what `bussard init` and the MCP
//! tool `knx_setup` both run (issue #745).
//!
//! [`run`] resolves the gateway (given, routing, or found by KNXnet/IP
//! discovery), writes the TOML skeleton, and imports the ETS export given or
//! the one found next to the directory: product data from the export,
//! vendor downloads only with the caller's consent, the keyring next to the
//! project into the key store, and a validation summary. It never prints and
//! never asks: every line goes to a [`ProgressSink`], every question to the
//! [`Prompt`] or a [`SetupHooks`] method. The CLI answers them on the terminal; the MCP tool
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

use crate::observer::{ProgressSink, Prompt};

pub use gateway::Resolution;
pub use skeleton::TargetState;

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

    /// Whether the project password given does not open the project
    /// ([`bussard_project::ImportError::WrongPassword`]).
    pub fn is_wrong_password(&self) -> bool {
        let source: &(dyn std::error::Error + 'static) = match self {
            SetupError::Source(source) | SetupError::Failed { source, .. } => source.as_ref(),
            SetupError::Message(_) | SetupError::PasswordRequired => return false,
        };
        let mut next = Some(source);
        while let Some(err) = next {
            if matches!(
                err.downcast_ref::<bussard_project::ImportError>(),
                Some(bussard_project::ImportError::WrongPassword)
            ) {
                return true;
            }
            next = err.source();
        }
        false
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

/// The questions a setup asks and the effects a surface supplies. Every
/// method has the answer of a caller that cannot ask: the MCP tool overrides
/// what its arguments settle, the CLI asks on the terminal. The product-data
/// download question goes to the [`Prompt`] ([`crate::observer::Ask::Download`]).
pub trait SetupHooks: Prompt {
    /// The KNXnet/IP gateways discovery finds on the local network.
    ///
    /// # Errors
    ///
    /// Discovery could not run.
    fn discover(&mut self) -> Result<Vec<GatewayInfo>, SetupError> {
        gateway::real_discover()
    }

    /// The best-effort reachability check of a gateway that was given.
    fn probe(&mut self, endpoint: std::net::SocketAddrV4, out: &mut dyn ProgressSink) {
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
    fn no_gateway(&mut self, out: &mut dyn ProgressSink) -> bool;

    /// Several gateways answered: the index of the one to use, or `None` to
    /// stop before anything is written.
    ///
    /// # Errors
    ///
    /// The choice could not be read, or the caller refuses to choose.
    fn choose_gateway(
        &mut self,
        found: &[GatewayInfo],
        out: &mut dyn ProgressSink,
    ) -> Result<Option<usize>, SetupError>;

    /// Several ETS projects lie next to `dir` and none was named: `true`
    /// goes on without one, `false` stops before anything is written.
    fn several_projects(
        &mut self,
        dir: &Path,
        found: &[PathBuf],
        out: &mut dyn ProgressSink,
    ) -> bool;

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
        out: &mut dyn ProgressSink,
    ) -> Result<u8, SetupError>
    where
        Self: Sized,
    {
        import::prepare_write(dir, out);
        import::write_fresh(model, dir, project, Some(self), out)?;
        Ok(0)
    }
}

/// What [`run`] is asked to do. Its `Debug` never shows the password.
#[derive(Clone, Default)]
pub struct SetupRequest {
    /// The model directory to create.
    pub dir: PathBuf,
    /// A gateway `host[:port]`; `None` discovers one.
    pub gateway: Option<String>,
    /// Configure KNXnet/IP routing (multicast) instead of a tunnel.
    pub routing: bool,
    /// The project to import (a `.knxproj`).
    pub project: Option<PathBuf>,
    /// Look for the one `.knxproj` next to `dir` when `project` is `None`.
    pub find_project: bool,
    /// The project password; `None` reads `BUSSARD_PROJECT_PASSWORD`.
    pub password: Option<String>,
}

impl std::fmt::Debug for SetupRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupRequest")
            .field("dir", &self.dir)
            .field("gateway", &self.gateway)
            .field("routing", &self.routing)
            .field("project", &self.project)
            .field("find_project", &self.find_project)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
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
    out: &mut dyn ProgressSink,
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
            let code = hooks.write_import(model, dir, Some(path.as_path()), out)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::Collected;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Hooks that answer like a caller who cannot ask, never touching the
    /// network.
    #[derive(Default)]
    struct Quiet {
        confirmed: bool,
    }

    impl Prompt for Quiet {}

    impl SetupHooks for Quiet {
        fn discover(&mut self) -> Result<Vec<GatewayInfo>, SetupError> {
            Ok(Vec::new())
        }

        fn probe(&mut self, _endpoint: std::net::SocketAddrV4, _out: &mut dyn ProgressSink) {}

        fn confirm_target(&mut self, _dir: &Path, _state: TargetState) -> Result<bool, SetupError> {
            Ok(self.confirmed)
        }

        fn no_gateway(&mut self, _out: &mut dyn ProgressSink) -> bool {
            false
        }

        fn choose_gateway(
            &mut self,
            _found: &[GatewayInfo],
            _out: &mut dyn ProgressSink,
        ) -> Result<Option<usize>, SetupError> {
            Ok(None)
        }

        fn several_projects(
            &mut self,
            _dir: &Path,
            _found: &[PathBuf],
            _out: &mut dyn ProgressSink,
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

    #[test]
    fn test_is_wrong_password_finds_the_import_error() {
        let wrong = SetupError::source(bussard_project::ImportError::WrongPassword);
        assert!(wrong.is_wrong_password());
        let wrapped = SetupError::Failed {
            context: "loading".to_string(),
            source: Box::new(bussard_project::ImportError::WrongPassword),
        };
        assert!(wrapped.is_wrong_password());
        assert!(!SetupError::PasswordRequired.is_wrong_password());
        assert!(!SetupError::Message("x".to_string()).is_wrong_password());
    }

    #[test]
    fn test_setup_request_debug_redacts_the_password() {
        let request = SetupRequest {
            password: Some("hunter2".to_string()),
            ..SetupRequest::default()
        };
        let text = format!("{request:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }
}
