//! The onboarding state of the server (issue #745): `bussard mcp --dir` on a
//! missing or empty directory.
//!
//! There is no model yet, so the server registers two tools only:
//! `knx_setup`, which runs the setup `bussard init` runs
//! ([`bussard_service::setup::run`]: the gateway, the skeleton, the import of
//! the ETS export given or found next to the directory), and a
//! `knx_bus_status` that says there is no bus connection until then. Once
//! `knx_setup` has written the model, the server loads it, opens the bus the
//! way a server started on that directory would, registers the full tool set
//! of the tiers it was started with and sends
//! `notifications/tools/list_changed`; from then on every request goes to
//! that [`BussardMcp`].
//!
//! The setup never asks on a terminal here. What the CLI would ask becomes a
//! `question` in the result with nothing written: several gateways, none
//! found, several projects, a directory that is no longer empty. The product
//! data download is the `download` argument, never a `yes`, and the project
//! password comes from `BUSSARD_PROJECT_PASSWORD` (the `.env` the server
//! reads) or the `password` argument, which no result or log line repeats.
//! Without either, a client with URL-mode elicitation gets bussard's
//! password form ([`crate::password_form`], #818): the human types the
//! password into a page on this computer, bussard stores it in the `.env`
//! and runs the setup with it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use bussard_bus::BusHandle;
use bussard_model::Model;
use bussard_service::BusService;
use bussard_service::observer::{Answer, Collected, ProgressSink, Prompt, Question};
use bussard_service::setup::{
    self, SetupError, SetupHooks, SetupOutcome, SetupRequest, TargetState,
};
use bussard_transport::ConnectionConfig;
use bussard_transport::knxnet::GatewayInfo;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::{InputResponses, RequestState};
use rmcp::model::{
    CallToolResponse, CallToolResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::schemars::{self, JsonSchema};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_router};
use serde::Deserialize;
use serde_json::json;

use crate::McpConfig;
use crate::args::Parameters;
use crate::password_form::{self, Attempt, PasswordForms, Step};
use crate::server::BussardMcp;

/// The tools of the onboarding state, in registration order.
pub const ONBOARDING_TOOLS: [&str; 2] = ["knx_setup", "knx_bus_status"];

/// Resolves the bus connection from the model `knx_setup` wrote, with the
/// overrides the server was started with (`--gateway`, `--routing`, the
/// KNXnet/IP Secure flags), and the keyring the model directory now has
/// (the key store the import wrote). The KNXnet/IP Secure tunnelling users
/// of that keyring are read here, after the setup, so a secure-only
/// interface works without a restart (issue #779).
pub type ResolveConnection =
    Arc<dyn Fn(&Model) -> anyhow::Result<ResolvedConnection> + Send + Sync + 'static>;

/// What [`ResolveConnection`] resolved from the model `knx_setup` wrote.
#[derive(Debug, Clone)]
pub struct ResolvedConnection {
    /// The bus connection, with the KNXnet/IP Secure tunnelling credentials
    /// of the keyring when it lists any.
    pub connection: ConnectionConfig,
    /// The keyring for KNX Data Secure (the key store the import wrote).
    pub keyring: Option<PathBuf>,
    /// A sentence for the `knx_setup` summary about the tunnel credentials:
    /// which ones the tunnel uses, or why it stays plain and what restart
    /// makes it secure. `None` when there is nothing to say.
    pub tunnel_note: Option<String>,
}

/// What the onboarding server needs to become the full server.
#[derive(Clone)]
pub struct Onboarding {
    /// The configuration of the full server. Its `connection` is a
    /// placeholder until `knx_setup` wrote `bussard.toml`; [`Self::resolve`]
    /// replaces it.
    pub config: McpConfig,
    /// Resolves the connection from the written model.
    pub resolve: ResolveConnection,
    /// The gateway `knx_setup` uses when its call names none (`--gateway`).
    pub default_gateway: Option<String>,
    /// `--routing`: `knx_setup` writes a routing model unless its call names
    /// a gateway.
    pub routing: bool,
}

impl std::fmt::Debug for Onboarding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Onboarding")
            .field("config", &self.config)
            .field("default_gateway", &self.default_gateway)
            .field("routing", &self.routing)
            .finish_non_exhaustive()
    }
}

/// Whether `dir` starts the server in the onboarding state: it is missing,
/// or empty apart from a repository's own files and bussard's local data
/// (`.git`, `.env`, `.gitignore`, `.bussard`), and holds no `bussard.toml`.
pub fn is_onboarding_dir(dir: &Path) -> bool {
    if dir.join(bussard_model::loader::CONFIG_FILE).is_file() {
        return false;
    }
    setup::skeleton::target_state(dir).is_ok_and(|state| !state.needs_confirmation())
}

/// The bus and instance marker the full server holds once it is active.
struct Running {
    /// The bus handle, closed when the server exits.
    handle: BusHandle,
    /// The ring feeder, aborted when the server exits.
    feeder: tokio::task::JoinHandle<()>,
    /// This process's instance marker for the model directory (issue #287).
    _instance: Option<bussard_transport::host_lock::HostLock>,
}

/// The shared part of every clone of [`SetupMcp`].
struct Inner {
    /// What the full server needs.
    onboarding: Onboarding,
    /// The full server, once `knx_setup` succeeded.
    full: OnceLock<BussardMcp>,
    /// The bus of the full server.
    running: std::sync::Mutex<Option<Running>>,
    /// One setup at a time.
    setup_lock: tokio::sync::Mutex<()>,
    /// The project password form `knx_setup` shows (#818).
    forms: PasswordForms,
}

/// The MCP server of the onboarding state: `knx_setup` and `knx_bus_status`
/// until the model exists, the full [`BussardMcp`] after.
#[derive(Clone)]
pub struct SetupMcp {
    /// The shared state.
    inner: Arc<Inner>,
    /// The onboarding tools.
    tool_router: ToolRouter<SetupMcp>,
}

impl std::fmt::Debug for SetupMcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupMcp")
            .field("dir", &self.inner.onboarding.config.dir)
            .field("active", &self.inner.full.get().is_some())
            .finish_non_exhaustive()
    }
}

/// Arguments for `knx_setup`. Its `Debug` never shows the password.
#[derive(Default, Deserialize, JsonSchema)]
pub struct SetupArgs {
    /// The ETS project export to import: a `.knxproj`, as a path on this
    /// computer. Omit it to import the one
    /// `.knxproj` lying next to the project folder, or to start without a
    /// project when there is none.
    #[serde(default)]
    pub project_file: Option<String>,
    /// The KNXnet/IP gateway as `host[:port]` (port 3671 by default), or
    /// `"routing"` for KNXnet/IP routing (multicast). Omit it to find the
    /// gateway by discovery on this computer's networks.
    #[serde(default)]
    pub gateway: Option<String>,
    /// Download the vendor product data (`.knxprod`) the export does not
    /// carry from bussard's product index. These are copyrighted vendor
    /// files: pass `true` only after the human agreed to the download. Off
    /// by default; without it the result names what is missing.
    #[serde(default)]
    pub download: bool,
    /// The project password, when the export is password-protected and
    /// `BUSSARD_PROJECT_PASSWORD` is not set in the `.env` the server reads.
    /// Never repeated in a result or a log line.
    #[serde(default)]
    pub password: Option<String>,
}

impl std::fmt::Debug for SetupArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupArgs")
            .field("project_file", &self.project_file)
            .field("gateway", &self.gateway)
            .field("download", &self.download)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running").finish_non_exhaustive()
    }
}

/// The answers of a chat to the setup's questions: what the call's arguments
/// settle, and a question for the assistant where the CLI would ask.
struct Chat {
    /// `download: true`.
    download: bool,
    /// The question that stopped the setup, for the result.
    question: Option<String>,
}

impl Prompt for Chat {
    fn ask(&mut self, _question: &Question) -> Answer {
        if self.download {
            Answer::Yes
        } else {
            Answer::No
        }
    }
}

impl SetupHooks for Chat {
    fn confirm_target(&mut self, dir: &Path, state: TargetState) -> Result<bool, SetupError> {
        self.question = Some(format!(
            "{} is no longer empty ({}). Nothing was written. Ask the owner to empty it, or \
             to set it up at the terminal with `bussard init --dir {} --yes`.",
            dir.display(),
            state.describe(),
            dir.display()
        ));
        Ok(false)
    }

    fn no_gateway(&mut self, _out: &mut dyn ProgressSink) -> bool {
        self.question = Some(
            "No KNXnet/IP gateway answered discovery on this computer's networks (discovery is \
             multicast and does not cross subnets). Nothing was written. Ask the owner for the \
             gateway's IP address (their router or Home Assistant's KNX settings list it) and \
             call knx_setup again with gateway; or gateway: \"routing\" for KNXnet/IP routing."
                .to_string(),
        );
        false
    }

    fn choose_gateway(
        &mut self,
        found: &[GatewayInfo],
        _out: &mut dyn ProgressSink,
    ) -> Result<Option<usize>, SetupError> {
        let list: Vec<String> = found.iter().map(setup::gateway::describe_gateway).collect();
        self.question = Some(format!(
            "Several KNXnet/IP gateways answered: {}. Nothing was written. Ask the owner which \
             one bussard should use, then call knx_setup again with gateway set to its address.",
            list.join("; ")
        ));
        Ok(None)
    }

    fn several_projects(
        &mut self,
        _dir: &Path,
        found: &[PathBuf],
        _out: &mut dyn ProgressSink,
    ) -> bool {
        let list: Vec<String> = found.iter().map(|p| p.display().to_string()).collect();
        self.question = Some(format!(
            "Several ETS projects lie next to the model directory: {}. Nothing was written. Ask \
             the owner which one is current, then call knx_setup again with project_file.",
            list.join(", ")
        ));
        false
    }
}

#[tool_router]
impl SetupMcp {
    // `knx_setup` (issue #745).
    #[doc = include_str!("../guidance/tools/onboarding/knx_setup.md")]
    #[tool]
    async fn knx_setup(
        &self,
        Parameters(args): Parameters<SetupArgs>,
        context: RequestContext<RoleServer>,
        RequestState(request_state): RequestState,
        InputResponses(input_responses): InputResponses,
    ) -> Result<CallToolResponse, ErrorData> {
        let _one = self.inner.setup_lock.lock().await;
        if self.inner.full.get().is_some() {
            return Ok(CallToolResult::structured(json!({
                "done": true,
                "summary": "The model is already set up; the full tool set is registered.",
            }))
            .into());
        }
        let onboarding = &self.inner.onboarding;
        let dir = onboarding.config.dir.clone();
        let (gateway, routing) = match args.gateway.as_deref().map(str::trim) {
            Some(g) if g.eq_ignore_ascii_case("routing") => (None, true),
            Some(g) if !g.is_empty() => (Some(g.to_string()), false),
            _ => (onboarding.default_gateway.clone(), onboarding.routing),
        };
        let request = SetupRequest {
            dir: dir.clone(),
            gateway,
            routing,
            project: args.project_file.as_deref().map(PathBuf::from),
            find_project: args.project_file.is_none(),
            password: args.password.clone(),
        };
        let download = args.download;
        let forms = &self.inner.forms;
        // The client's second round of a 2026-07-28 call: the human's answer
        // to the password form's elicitation (#818).
        if let Some(state) = request_state.filter(|s| password_form::is_form_state(s)) {
            return Ok(
                match password_form::resume(forms, &state, input_responses.as_ref()) {
                    Step::Open(form) => self.setup_with_form(form, request, download).await.into(),
                    Step::Answer(answer) => answer,
                    Step::Unsupported => password_required(Vec::new()).into(),
                },
            );
        }
        let (outcome, question, log) = run_setup(request.clone(), download).await;
        // No password, or a wrong one from the .env: the form, when the
        // client can show it (#818).
        let needs_password = match &outcome {
            Err(SetupError::PasswordRequired) => true,
            Err(err) => args.password.is_none() && err.is_wrong_password(),
            Ok(_) => false,
        };
        if needs_password {
            match password_form::ask(forms, &context, project_name(&request)).await {
                Step::Open(form) => {
                    return Ok(self.setup_with_form(form, request, download).await.into());
                }
                Step::Answer(answer) => return Ok(answer),
                Step::Unsupported => {}
            }
        }
        Ok(self.finish_setup(outcome, question, log, None).await.into())
    }

    // `knx_bus_status` before the model exists.
    #[doc = include_str!("../guidance/tools/onboarding/knx_bus_status.md")]
    #[tool]
    async fn knx_bus_status(&self) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::structured(json!({
            "state": "no_model",
            "connected": false,
            "reason": format!(
                "There is no model in {} yet, so there is no bus connection. Call knx_setup: \
                 it finds the gateway and writes the model.",
                self.inner.onboarding.config.dir.display()
            ),
        })))
    }
}

/// The refusal when the project needs a password and the form cannot be
/// shown.
fn password_required(log: Vec<String>) -> CallToolResult {
    failure(
        "The project is password-protected. Nothing was written. Ask the owner to put \
         BUSSARD_PROJECT_PASSWORD=<password> in the .env next to the model directory (the \
         server reads it), or pass the password as `password`."
            .to_string(),
        log,
    )
}

/// What a setup run returns: the outcome, the question a hook asked, the
/// lines it said.
type SetupRun = (
    Result<SetupOutcome, SetupError>,
    Option<String>,
    Vec<String>,
);

/// Runs the setup of `request` on a blocking thread, answering its
/// questions as a chat does.
async fn run_setup(request: SetupRequest, download: bool) -> SetupRun {
    let joined = tokio::task::spawn_blocking(move || {
        let mut hooks = Chat {
            download,
            question: None,
        };
        let mut out = Collected::default();
        let outcome = setup::run(&request, &mut hooks, &mut out);
        (outcome, hooks.question, out.lines)
    })
    .await;
    joined.unwrap_or_else(|err| {
        (
            Err(SetupError::Message(format!("the setup stopped: {err}"))),
            None,
            Vec::new(),
        )
    })
}

/// The file name of the project `request` imports, for the password form.
fn project_name(request: &SetupRequest) -> Option<String> {
    let project = match &request.project {
        Some(project) => Some(project.clone()),
        None => match setup::skeleton::find_project(&request.dir) {
            setup::skeleton::ProjectSearch::One(found) => Some(found),
            _ => None,
        },
    };
    project
        .as_deref()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
}

/// A tool error result: the sentence and the lines the setup said.
fn failure(sentence: String, log: Vec<String>) -> CallToolResult {
    let mut result = CallToolResult::structured(json!({
        "done": false,
        "error": sentence,
        "log": log,
    }));
    result.is_error = Some(true);
    result
}

impl SetupMcp {
    /// The onboarding server for `onboarding.config.dir`.
    pub fn new(onboarding: Onboarding) -> Self {
        SetupMcp {
            inner: Arc::new(Inner {
                onboarding,
                full: OnceLock::new(),
                running: std::sync::Mutex::new(None),
                setup_lock: tokio::sync::Mutex::new(()),
                forms: PasswordForms::new(),
            }),
            tool_router: Self::tool_router(),
        }
    }

    /// Collects the project password from `form` and runs the setup with
    /// it (#818).
    async fn setup_with_form(
        &self,
        form: Arc<password_form::PendingForm>,
        request: SetupRequest,
        download: bool,
    ) -> CallToolResult {
        let dir = request.dir.clone();
        let collected = password_form::collect(form, &dir, "set the project up", |password| {
            let mut request = request.clone();
            request.password = Some(password.expose().to_string());
            async move {
                let (outcome, question, log) = run_setup(request, download).await;
                match outcome {
                    Err(err) if err.is_wrong_password() => Attempt::WrongPassword,
                    Ok(outcome) => Attempt::Opened((Ok(outcome), question, log)),
                    Err(err) => Attempt::Failed((Err(err), question, log)),
                }
            }
        })
        .await;
        match collected {
            password_form::Collected::Opened {
                value: (outcome, question, log),
                stored,
            } => {
                self.finish_setup(
                    outcome,
                    question,
                    log,
                    Some(password_form::stored_note(&stored)),
                )
                .await
            }
            password_form::Collected::Failed((outcome, question, log)) => {
                self.finish_setup(outcome, question, log, None).await
            }
            password_form::Collected::Ended(reason) => password_form::ended(&reason),
        }
    }

    /// The result of a setup run: the failure or question it ended with,
    /// or the full server it activated. `password` says where the project
    /// password came from when it was the form.
    async fn finish_setup(
        &self,
        outcome: Result<SetupOutcome, SetupError>,
        question: Option<String>,
        log: Vec<String>,
        password: Option<String>,
    ) -> CallToolResult {
        let dir = self.inner.onboarding.config.dir.clone();
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(SetupError::PasswordRequired) => return password_required(log),
            Err(err) => {
                return failure(
                    format!("The setup failed: {}", setup::products::error_chain(&err)),
                    log,
                );
            }
        };
        let imported = match outcome {
            SetupOutcome::Written { imported, .. } => imported,
            // Someone set the model up meanwhile (`bussard init` at the
            // terminal): load it as it is.
            SetupOutcome::HasModel => None,
            SetupOutcome::NotConfirmed | SetupOutcome::Stopped => {
                return CallToolResult::structured(json!({
                    "done": false,
                    "question": question.unwrap_or_else(|| "Nothing was written.".to_string()),
                    "log": log,
                }));
            }
        };
        match self.activate().await {
            Ok((full, tunnel_note)) => {
                let tools = full.tool_count();
                let instructions = crate::guidance::Tiers::of(full.state()).instructions();
                let summary = match &imported {
                    Some((project, 0)) => format!(
                        "Set up {} from {}. The server now has its full tool set ({tools} \
                         tools); continue with knx_project_summary.",
                        dir.display(),
                        project.display()
                    ),
                    Some((project, _)) => format!(
                        "Set up {} from {}, with conflicts the log names. The server now has \
                         its full tool set ({tools} tools); continue with knx_project_summary.",
                        dir.display(),
                        project.display()
                    ),
                    None => format!(
                        "Set up {} without an ETS project. The server now has its full tool \
                         set ({tools} tools); continue with knx_project_summary, then build the \
                         model with the edit tools or import an export at the terminal \
                         (`bussard import <project.knxproj> --dir {}`).",
                        dir.display(),
                        dir.display()
                    ),
                };
                let summary = match &tunnel_note {
                    Some(note) => format!("{summary} {note}"),
                    None => summary,
                };
                let mut result = json!({
                    "done": true,
                    "dir": dir.display().to_string(),
                    "project": imported.as_ref().map(|(p, _)| p.display().to_string()),
                    "summary": summary,
                    "tools": tools,
                    "log": log,
                    "instructions": instructions,
                });
                if let Some(password) = password {
                    result["password"] = json!(password);
                }
                CallToolResult::structured(result)
            }
            Err(reason) => failure(
                format!(
                    "The model was written to {}, but the server could not load it: {reason}. \
                     Restart the server (the MCP client reconnects it) to use it.",
                    dir.display()
                ),
                log,
            ),
        }
    }

    /// The full server, once `knx_setup` succeeded.
    pub fn full(&self) -> Option<&BussardMcp> {
        self.inner.full.get()
    }

    /// Loads the written model, opens the bus under the server's write
    /// policy, wires the ring feeder and registers the full server.
    /// Returns the full server and the tunnel sentence for the summary.
    async fn activate(&self) -> Result<(&BussardMcp, Option<String>), String> {
        let onboarding = &self.inner.onboarding;
        let dir = onboarding.config.dir.clone();
        let model = Model::load(&dir).map_err(|e| format!("the model does not load: {e}"))?;
        let ResolvedConnection {
            connection,
            keyring,
            tunnel_note,
        } = (onboarding.resolve)(&model).map_err(|e| format!("{e:#}"))?;
        let mut config = onboarding.config.clone();
        config.connection = connection;
        if config.keyring.is_none() {
            config.keyring = keyring;
        }
        let state = crate::build_state(&config).map_err(|e| format!("{e:#}"))?;
        let instance = crate::instances::register(&dir);
        let service = BusService::open(config.connection.clone(), config.write_policy())
            .map_err(|e| e.to_string())?;
        if service.gate() == Some(bussard_transport::write_gate::WriteGate::OptedIn) {
            tracing::warn!(
                "{}",
                bussard_service::guidance::opt_in_warning(&service.gateway_display())
            );
        }
        let (handle, feeder) = crate::run::wire_bus(&state, service);
        let full = BussardMcp::new(state);
        tracing::info!(
            "mcp: knx_setup wrote {}; {} tools registered",
            dir.display(),
            full.tool_count()
        );
        if let Ok(mut running) = self.inner.running.lock() {
            *running = Some(Running {
                handle,
                feeder,
                _instance: instance,
            });
        }
        // `knx_setup` holds the setup lock, so no other call sets it.
        let _ = self.inner.full.set(full);
        self.inner
            .full
            .get()
            .map(|full| (full, tunnel_note))
            .ok_or_else(|| "the full server did not register".to_string())
    }

    /// Closes the bus of the full server, when there is one.
    pub async fn shutdown(&self) {
        if let Some(full) = self.inner.full.get() {
            full.state().viz.stop().await;
        }
        let running = self.inner.running.lock().ok().and_then(|mut r| r.take());
        if let Some(running) = running {
            let _ = running.handle.close().await;
            running.feeder.abort();
        }
    }

    /// The onboarding server instructions.
    fn instructions(&self) -> String {
        format!(
            "bussard: KNX as code over MCP. There is no model in {} yet, so only knx_setup and \
             knx_bus_status are registered. To set the house up, ask the human whether they \
             have an ETS project export (.knxproj) and where it lies, then call knx_setup \
             (with project_file when it is not next to the model directory). knx_setup finds \
             the gateway on the local network, writes the model and imports the export. \
             Downloading vendor product data needs the human's agreement first (download: \
             true). When knx_setup returns a question, nothing was written: relay it and call \
             again. After it succeeds the server registers its full tool set and its result \
             carries the instructions for it; start with knx_project_summary.",
            self.inner.onboarding.config.dir.display()
        )
    }
}

impl ServerHandler for SetupMcp {
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, ErrorData> {
        if let Some(full) = self.inner.full.get() {
            return full.call_tool(request, context).await;
        }
        tracing::info!(
            tool = %request.name,
            arguments_present = request.arguments.is_some(),
            fields = ?crate::args::field_names(request.arguments.as_ref()),
            "tools/call"
        );
        let peer = context.peer.clone();
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let result = crate::args::argument_error_as_tool_result(self.tool_router.call(tcc).await);
        if self.inner.full.get().is_some()
            && let Err(err) = peer.notify_tool_list_changed().await
        {
            tracing::warn!("failed to send tools/list_changed: {err}");
        }
        result
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if let Some(full) = self.inner.full.get() {
            return full.list_tools(request, context).await;
        }
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            ..ListToolsResult::default()
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        match self.inner.full.get() {
            Some(full) => full.get_tool(name),
            None => self.tool_router.get(name).cloned(),
        }
    }

    fn get_info(&self) -> ServerInfo {
        let mut server_info = rmcp::model::Implementation::from_build_env();
        server_info.name = "bussard".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        server_info.title = Some("bussard KNX MCP server".to_string());
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_server_info(server_info)
        .with_instructions(self.instructions())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn scratch(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir =
            std::env::temp_dir().join(format!("bussard-onboarding-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn test_is_onboarding_dir_missing_empty_and_model() -> TestResult {
        let dir = scratch("dirs")?;
        assert!(
            is_onboarding_dir(&dir.join("absent")),
            "a missing directory"
        );
        assert!(is_onboarding_dir(&dir), "an empty directory");
        std::fs::write(dir.join(".env"), "BUSSARD_PROJECT_PASSWORD=x\n")?;
        assert!(is_onboarding_dir(&dir), ".env does not count");
        std::fs::write(dir.join("notes.txt"), "mine")?;
        assert!(!is_onboarding_dir(&dir), "a non-empty directory");
        let model = dir.join("model");
        std::fs::create_dir_all(&model)?;
        std::fs::write(model.join("bussard.toml"), "[connection]\n")?;
        assert!(!is_onboarding_dir(&model), "a model directory");
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_setup_args_debug_redacts_the_password() {
        let args = SetupArgs {
            password: Some("hunter2".to_string()),
            ..SetupArgs::default()
        };
        let text = format!("{args:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    #[test]
    fn test_chat_hooks_turn_questions_into_a_question() -> TestResult {
        let dir = scratch("chat")?;
        let mut chat = Chat {
            download: false,
            question: None,
        };
        let mut out = Collected::default();
        let request = SetupRequest {
            dir: dir.join("knx"),
            find_project: true,
            ..SetupRequest::default()
        };
        std::fs::write(dir.join("a.knxproj"), "x")?;
        std::fs::write(dir.join("b.knxproj"), "y")?;
        let outcome = setup::run(&request, &mut chat, &mut out)?;
        assert!(matches!(outcome, SetupOutcome::Stopped), "{outcome:?}");
        let question = chat.question.ok_or("a question")?;
        assert!(
            question.contains("a.knxproj") && question.contains("b.knxproj"),
            "{question}"
        );
        assert!(!dir.join("knx").exists(), "nothing was written");
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }
}
