//! File import and export tools (issues #743, #744).
//!
//! `knx_import_file` brings in what ETS or a vendor hands over: a `.knxproj`,
//! a `.bussard` bundle, a `.knxprod` (or vendor product data by order
//! number) or a `.knxkeys` keyring. `knx_export` writes
//! the bundle, the group plan for ETS, the keyring or the handover
//! documentation. Both run the functions `bussard import`, `bussard
//! import-product`, `bussard keys`, `bussard export`, `bussard export-groups`
//! and `bussard doc` run ([`bussard_service::files`], #314), and both only
//! touch files, never the bus, so they are registered in every tier.
//! `knx_import_file` writes the model and is withheld by `--no-model-edits`.
//!
//! Consent to download vendor product data is the `download` argument, never
//! `yes`. A password argument is never echoed, and no result carries key
//! material: keyring results are addresses and counts. A protected
//! `.knxproj` without a password gets bussard's password form when the
//! client shows URLs ([`crate::password_form`], #818).

use std::path::{Path, PathBuf};

use bussard_model::Model;
use bussard_project::keystore::SaveOutcome;
use bussard_service::files::export::GroupFormat;
use bussard_service::files::import::{ConflictChoice, ImportOutcome, NoPrompt};
use bussard_service::files::products::OrderImport;
use bussard_service::files::{FileKind, export, import, keyring, products};
use bussard_service::secure::KEYRING_PASSWORD_ENV;
use bussard_service::setup::products::error_chain;
use bussard_service::setup::{self, Collected, DownloadAnswer, DownloadPrompt, SetupError};
use std::sync::Arc;

use rmcp::handler::server::tool::{InputResponses, RequestState};
use rmcp::model::{CallToolResponse, CallToolResult};
use rmcp::schemars::{self, JsonSchema};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::args::Parameters;
use crate::password_form::{self, Attempt, Step};
use crate::server::BussardMcp;

/// The export tool, registered in every tier. `knx_import_file` writes the
/// model and is listed with [`crate::tools_model::MODEL_EDIT_TOOLS`].
pub const EXPORT_TOOLS: [&str; 1] = ["knx_export"];

/// How a download is consented to over MCP, for the refusal sentence.
const CONSENT_HINT: &str = "it is copyrighted vendor product data fetched over the network; \
    ask the human, then call knx_import_file again with download: true";

/// The download question over MCP: the `download` argument answers it.
struct ChatDownload {
    /// The human agreed (`download: true`).
    download: bool,
}

impl DownloadPrompt for ChatDownload {
    fn download(&mut self, _question: &str, files: usize) -> Result<DownloadAnswer, SetupError> {
        Ok(if self.download {
            DownloadAnswer::Yes
        } else {
            let what = if files == 1 {
                "this file".to_string()
            } else {
                format!("{files} file(s)")
            };
            DownloadAnswer::Refused(format!("not downloading {what}: {CONSENT_HINT}"))
        })
    }
}

/// Arguments for `knx_import_file`.
#[derive(Default, Deserialize, JsonSchema)]
pub struct ImportFileArgs {
    /// The file to import: a `.knxproj` (ETS project export), a `.bussard`
    /// bundle, a `.knxprod` (vendor product data) or a `.knxkeys` (ETS
    /// keyring). Give this or `order_number`.
    #[serde(default)]
    pub path: Option<String>,
    /// Fetch vendor product data by order number from bussard's product
    /// index instead of a file. Needs `download: true`.
    #[serde(default)]
    pub order_number: Option<String>,
    /// The human agreed to download vendor product data (for
    /// `order_number`, and for the devices of a `.knxproj` without product
    /// data). Default false: nothing is downloaded and the result says what
    /// would be.
    #[serde(default)]
    pub download: Option<bool>,
    /// The project password of a protected `.knxproj`, or the keyring
    /// password of a `.knxkeys` (the key store `bussard.keys` is encrypted
    /// with it). Falls back to the server's `BUSSARD_PROJECT_PASSWORD` or
    /// `BUSSARD_KEYRING_PASSWORD`. Never echoed, never stored.
    #[serde(default)]
    pub password: Option<String>,
    /// On a re-import, take the incoming value for every hand-edited field
    /// that differs (default false: keep the project's values and list them).
    #[serde(default)]
    pub theirs: Option<bool>,
}

impl std::fmt::Debug for ImportFileArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportFileArgs")
            .field("path", &self.path)
            .field("order_number", &self.order_number)
            .field("download", &self.download)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("theirs", &self.theirs)
            .finish()
    }
}

/// Arguments for `knx_export`.
#[derive(Default, Deserialize, JsonSchema)]
pub struct ExportArgs {
    /// What to write: `bundle` (the project and its history as one `.bussard`
    /// file), `groups` (the group-address plan for ETS's import), `keyring`
    /// (the key store as a signed `.knxkeys` ETS accepts) or `doc` (the
    /// handover documentation folder).
    pub what: String,
    /// Where to write. Optional for `bundle` (default: next to the project
    /// folder, named after it and today's date); required otherwise (a
    /// file for `groups` and `keyring`, a directory for `doc`).
    #[serde(default)]
    pub out: Option<String>,
    /// `groups`: `ets-csv` (default) or `ets-xml`. `doc`: `md` (the only
    /// format).
    #[serde(default)]
    pub format: Option<String>,
    /// `bundle`: include the history snapshots (default true).
    #[serde(default)]
    pub include_history: Option<bool>,
    /// `keyring`: the key store password; falls back to the server's
    /// `BUSSARD_KEYRING_PASSWORD`. Never echoed.
    #[serde(default)]
    pub password: Option<String>,
    /// `keyring`: overwrite an existing file (default false).
    #[serde(default)]
    pub force: Option<bool>,
}

impl std::fmt::Debug for ExportArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportArgs")
            .field("what", &self.what)
            .field("out", &self.out)
            .field("format", &self.format)
            .field("include_history", &self.include_history)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("force", &self.force)
            .finish()
    }
}

// `pub(crate)`: the router is combined in `BussardMcp::new` and needs no public
// face (a `pub` macro-generated fn could not carry the doc comment the crate
// requires).
#[tool_router(router = files_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_import_file`.
    #[tool(
        description = "Import a file from ETS or a vendor into the project, as `bussard import`, \
        `bussard import-product` and `bussard keys import` do, chosen by the file type: a \
        .knxproj (ETS project export) or .bussard bundle is written into the project (a re-import keeps hand-edited names, rooms and descriptions and lists \
        each one that differs; pass theirs: true to take the incoming values); a .knxprod is \
        stored as product data and its product models generated; a .knxkeys is merged into the \
        key store bussard.keys. Vendor product data by order number: {order_number, download: \
        true}. Downloading copyrighted vendor data needs the human's consent: ask, then pass \
        download: true (never `yes`); without it nothing is downloaded and the result says what \
        would be. A protected .knxproj the server has no password for: when the chat app \
        shows links, bussard shows the human its own password form on this computer, stores \
        the password in .env and imports; never ask for it in chat. Otherwise the result asks \
        for `password`. A .knxkeys needs `password` (ask the human; it is never echoed or \
        stored) unless the server's environment has it. Run knx_diff_project \
        first and quote its sentences before importing a project or bundle. Snapshots the \
        project first (knx_undo puts it back); touches no device. Returns sentences: quote the \
        summary."
    )]
    async fn knx_import_file(
        &self,
        Parameters(args): Parameters<ImportFileArgs>,
        context: RequestContext<RoleServer>,
        RequestState(request_state): RequestState,
        InputResponses(input_responses): InputResponses,
    ) -> Result<CallToolResponse, ErrorData> {
        if self.state().no_model_edits {
            return refusal("this server was started with --no-model-edits").map(Into::into);
        }
        let dir = self.state().dir.clone();
        let args = Arc::new(args);
        // The client's second round of a 2026-07-28 call: the human's answer
        // to the password form's elicitation (#818).
        if let Some(state) = request_state.filter(|s| password_form::is_form_state(s)) {
            return Ok(
                match password_form::resume(&self.password_forms, &state, input_responses.as_ref())
                {
                    Step::Open(form) => self.import_with_form(form, &args).await.into(),
                    Step::Answer(answer) => answer,
                    Step::Unsupported => CallToolResult::structured(refused(
                        "the password form is closed",
                        &Collected::default(),
                    ))
                    .into(),
                },
            );
        }
        let Some(path) = project_path(&args) else {
            let thread_args = Arc::clone(&args);
            let result = tokio::task::spawn_blocking(move || import_file(&dir, &thread_args)).await;
            // Whatever the import wrote, the server reads the files afresh.
            self.state().model.reload();
            return match result {
                Ok(Ok(value) | Err(value)) => ok(value),
                Err(err) => refusal(format!("the import did not finish: {err}")),
            }
            .map(Into::into);
        };
        let run = run_project_import(&dir, &path, &args, None).await;
        self.state().model.reload();
        // No password, or a wrong one from the .env: the form, when the
        // client can show it (#818).
        let needs_password = match &run {
            ProjectRun::PasswordRequired(_) => true,
            ProjectRun::WrongPassword(_) => args.password.is_none(),
            ProjectRun::Done(_) | ProjectRun::Failed(_) => false,
        };
        if needs_password {
            let file = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            match password_form::ask(&self.password_forms, &context, file).await {
                Step::Open(form) => return Ok(self.import_with_form(form, &args).await.into()),
                Step::Answer(answer) => return Ok(answer),
                Step::Unsupported => {}
            }
        }
        ok(run.into_value()).map(Into::into)
    }

    /// `knx_export`.
    #[tool(
        description = "Write an export of the project, as `bussard export`, `bussard \
        export-groups`, `bussard keys export` and `bussard doc` do. what: `bundle` writes the \
        project and its history as one .bussard file (the handover file for an integrator, or the \
        owner's backup; never vendor product data, keyrings or passwords; `out` optional); \
        `groups` writes the group-address plan for ETS's Group Addresses -> Import (format \
        ets-csv or ets-xml); `keyring` writes the key store as a signed .knxkeys ETS accepts, \
        reads it back and says whether it carries every key (needs the keyring `password` \
        unless the server's environment has it; force: true to overwrite); `doc` renders the \
        handover documentation folder as Markdown. Returns the written path and one \
        summary sentence; never key material. Touches no device and no project file."
    )]
    async fn knx_export(
        &self,
        Parameters(args): Parameters<ExportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let dir = self.state().dir.clone();
        let result = tokio::task::spawn_blocking(move || export_file(&dir, &args)).await;
        match result {
            Ok(Ok(value) | Err(value)) => ok(value),
            Err(err) => refusal(format!("the export did not finish: {err}")),
        }
    }
}

/// Runs `knx_import_file`: the result, or the refusal, as JSON.
fn import_file(dir: &Path, args: &ImportFileArgs) -> Result<Value, Value> {
    let mut prompt = ChatDownload {
        download: args.download.unwrap_or(false),
    };
    let mut out = Collected::default();
    match (args.path.as_deref(), args.order_number.as_deref()) {
        (Some(_), Some(_)) => Err(refused("give either path or order_number, not both", &out)),
        (None, None) => Err(refused(
            "give path (a .knxproj, .bussard, .knxprod or .knxkeys file) or \
             order_number with download: true",
            &out,
        )),
        (None, Some(order)) => {
            match products::import_product_order(order, dir, None, &mut prompt, &mut out) {
                Ok(OrderImport::Imported(product)) => Ok(product_result(
                    "order_number",
                    order,
                    &product.stored,
                    &product.models,
                    &out,
                )),
                Ok(OrderImport::Declined) => {
                    Err(refused(format!("{order} was not downloaded"), &out))
                }
                Err(err) => Err(refused(error_chain(&err), &out)),
            }
        }
        (Some(raw), None) => {
            let path = PathBuf::from(raw);
            match FileKind::of(&path) {
                Some(FileKind::Project) => {
                    match import_project(dir, &path, args, None, &mut prompt, &mut out) {
                        ProjectRun::Done(value) => Ok(value),
                        run => Err(run.into_value()),
                    }
                }
                Some(FileKind::Bundle) => {
                    match import::import_bundle(&path, dir, choice(args), &mut NoPrompt, &mut out) {
                        Ok(outcome) => Ok(model_result("bundle", &path, dir, &outcome, &out)),
                        Err(err) => Err(refused(error_chain(&err), &out)),
                    }
                }
                Some(FileKind::Product) => {
                    match products::import_product_file(&path, dir, None, &mut out) {
                        Ok(product) => Ok(product_result(
                            "path",
                            raw,
                            &product.stored,
                            &product.models,
                            &out,
                        )),
                        Err(err) => Err(refused(error_chain(&err), &out)),
                    }
                }
                Some(FileKind::Keyring) => import_keyring(dir, &path, args, &out),
                None => Err(refused(
                    format!(
                        "{raw} is not a file bussard imports: give a .knxproj, .bussard, \
                         .knxprod or .knxkeys"
                    ),
                    &out,
                )),
            }
        }
    }
}

/// The conflict choice of a re-import.
fn choice(args: &ImportFileArgs) -> ConflictChoice {
    if args.theirs.unwrap_or(false) {
        ConflictChoice::Theirs
    } else {
        ConflictChoice::Report
    }
}

/// A non-empty password: the argument, else the environment variable `env`.
fn password(arg: Option<&String>, env: &str) -> Option<String> {
    arg.cloned()
        .or_else(|| bussard_model::dotenv::var(env).ok())
        .filter(|s| !s.is_empty())
}

/// How a project import ended, each with its result.
enum ProjectRun {
    /// Imported.
    Done(Value),
    /// The project is password-protected and no password was given.
    PasswordRequired(Value),
    /// The password given does not open the project.
    WrongPassword(Value),
    /// Another refusal.
    Failed(Value),
}

impl ProjectRun {
    /// The tool result.
    fn into_value(self) -> Value {
        match self {
            ProjectRun::Done(value)
            | ProjectRun::PasswordRequired(value)
            | ProjectRun::WrongPassword(value)
            | ProjectRun::Failed(value) => value,
        }
    }
}

/// The `.knxproj` `args` imports, when it imports one by `path`.
fn project_path(args: &ImportFileArgs) -> Option<PathBuf> {
    if args.order_number.is_some() {
        return None;
    }
    let path = PathBuf::from(args.path.as_deref()?);
    matches!(FileKind::of(&path), Some(FileKind::Project)).then_some(path)
}

/// [`import_project`] on a blocking thread, with `password` in place of the
/// argument when given.
async fn run_project_import(
    dir: &Path,
    path: &Path,
    args: &Arc<ImportFileArgs>,
    password: Option<String>,
) -> ProjectRun {
    let (dir, path, args) = (dir.to_path_buf(), path.to_path_buf(), Arc::clone(args));
    let joined = tokio::task::spawn_blocking(move || {
        let mut prompt = ChatDownload {
            download: args.download.unwrap_or(false),
        };
        let mut out = Collected::default();
        import_project(&dir, &path, &args, password, &mut prompt, &mut out)
    })
    .await;
    joined.unwrap_or_else(|err| {
        ProjectRun::Failed(refused(
            format!("the import did not finish: {err}"),
            &Collected::default(),
        ))
    })
}

impl BussardMcp {
    /// Collects the project password from `form` and imports the project of
    /// `args` with it (#818).
    async fn import_with_form(
        &self,
        form: Arc<password_form::PendingForm>,
        args: &Arc<ImportFileArgs>,
    ) -> CallToolResult {
        let dir = self.state().dir.clone();
        let Some(path) = project_path(args) else {
            return CallToolResult::structured(refused(
                "the password form is for a .knxproj import",
                &Collected::default(),
            ));
        };
        let collected = password_form::collect(form, &dir, "imported the project", |password| {
            let (dir, path, args) = (dir.clone(), path.clone(), Arc::clone(args));
            async move {
                match run_project_import(&dir, &path, &args, Some(password.expose().to_string()))
                    .await
                {
                    ProjectRun::Done(value) => Attempt::Opened(value),
                    ProjectRun::WrongPassword(_) => Attempt::WrongPassword,
                    ProjectRun::PasswordRequired(value) | ProjectRun::Failed(value) => {
                        Attempt::Failed(value)
                    }
                }
            }
        })
        .await;
        self.state().model.reload();
        match collected {
            password_form::Collected::Opened { mut value, stored } => {
                value["password"] = json!(password_form::stored_note(&stored));
                CallToolResult::structured(value)
            }
            password_form::Collected::Failed(value) => CallToolResult::structured(value),
            password_form::Collected::Ended(reason) => password_form::ended(&reason),
        }
    }
}

/// Imports a `.knxproj` as `bussard import` does: loaded
/// with the project password ([`setup::import::load_project`]; `password`,
/// else the argument, else the server's), written over the model
/// ([`import::write_model`]), then the one `.knxkeys` next to it merged
/// into the key store ([`setup::import::import_neighbour`]).
fn import_project(
    dir: &Path,
    path: &Path,
    args: &ImportFileArgs,
    password: Option<String>,
    prompt: &mut ChatDownload,
    out: &mut Collected,
) -> ProjectRun {
    let given = password
        .or_else(|| args.password.clone())
        .filter(|s| !s.is_empty());
    let had_password = given.is_some();
    let model = match setup::import::load_project(path, dir, given, || Ok(None)) {
        Ok(model) => model,
        Err(SetupError::PasswordRequired) => {
            return ProjectRun::PasswordRequired(refused(
                format!(
                    "{} is password-protected; ask the human for the project password and pass \
                     it as password (it is never echoed or stored)",
                    path.display()
                ),
                out,
            ));
        }
        Err(err) => {
            let hint = if had_password {
                "; if the password is wrong, ask the human again (never guess one)"
            } else {
                ""
            };
            let value = refused(
                format!(
                    "{} could not be read: {}{hint}",
                    path.display(),
                    error_chain(&err)
                ),
                out,
            );
            return if err.is_wrong_password() {
                ProjectRun::WrongPassword(value)
            } else {
                ProjectRun::Failed(value)
            };
        }
    };
    let project = Some(path);
    let written = import::write_model(
        model,
        dir,
        choice(args),
        "project",
        Some(prompt),
        project,
        &mut NoPrompt,
        out,
    );
    match written {
        Ok(outcome) => {
            setup::import::import_neighbour(path, dir, out);
            ProjectRun::Done(model_result("project", path, dir, &outcome, out))
        }
        Err(err) => ProjectRun::Failed(refused(error_chain(&err), out)),
    }
}

/// The result of a project or bundle import.
fn model_result(
    source: &str,
    path: &Path,
    dir: &Path,
    outcome: &ImportOutcome,
    out: &Collected,
) -> Value {
    let name = file_name(path);
    let counts = Model::load(dir)
        .ok()
        .map(|m| (m.devices.len(), m.groups.groups.len()));
    let mut summary = match (outcome.written, counts) {
        (false, _) => format!("The model already matched {name}; no file was written."),
        (true, Some((devices, groups))) => format!(
            "Imported {name} into the model: {devices} device(s), {groups} group address(es)."
        ),
        (true, None) => format!("Imported {name} into the model."),
    };
    if outcome.unresolved {
        summary.push_str(&format!(
            " {} hand-edited field(s) differ from the {source} and were kept; pass theirs: true \
             to take the {source}'s values.",
            outcome.kept
        ));
    }
    json!({
        "ok": true,
        "kind": source,
        "path": path.display().to_string(),
        "summary": summary,
        "written": outcome.written,
        "merged": outcome.merged,
        "conflicts": outcome.conflicts,
        "kept": outcome.kept,
        "sentences": sentences(out),
    })
}

/// The result of a product-data import.
fn product_result(
    key: &str,
    value: &str,
    stored: &str,
    models: &[String],
    out: &Collected,
) -> Value {
    json!({
        "ok": true,
        "kind": "product",
        key: value,
        "summary": format!(
            "{stored}; generated {} product model(s): {}.",
            models.len(),
            models.join(", ")
        ),
        "models": models,
        "sentences": sentences(out),
    })
}

/// Merges a `.knxkeys` into the key store, as `bussard keys import` does
/// ([`setup::import::import_keyring_with`]).
fn import_keyring(
    dir: &Path,
    path: &Path,
    args: &ImportFileArgs,
    out: &Collected,
) -> Result<Value, Value> {
    let Some(password) = password(args.password.as_ref(), KEYRING_PASSWORD_ENV) else {
        return Err(refused(
            format!(
                "{} needs the keyring password: ask the human and pass it as password (it is \
                 never echoed or stored; the key store bussard.keys is encrypted with it)",
                path.display()
            ),
            out,
        ));
    };
    let (report, outcome) = setup::import::import_keyring_with(dir, path, &password)
        .map_err(|err| refused(error_chain(&err), out))?;
    let warnings: Vec<Value> = setup::import::rekeyed_warnings(dir, &report)
        .iter()
        .map(|d| json!({"code": d.code, "location": d.location, "message": d.message}))
        .collect();
    let what = match outcome {
        SaveOutcome::Written { backup: false } => "created",
        SaveOutcome::Written { backup: true } => "updated",
        SaveOutcome::Unchanged => "already up to date",
    };
    let summary = format!(
        "Merged the ETS keyring {} into the key store bussard.keys ({what}): {} device(s) \
         added, {} tool key(s) rotated, {} group key(s) added, {} rotated.",
        file_name(path),
        report.devices_added.len(),
        report.tool_keys_rotated.len(),
        report.group_keys_added.len(),
        report.group_keys_rotated.len(),
    );
    Ok(json!({
        "ok": true,
        "kind": "keyring",
        "path": path.display().to_string(),
        "store": bussard_project::KeyStore::path(dir).display().to_string(),
        "summary": summary,
        "changed": report.changed(),
        "report": report,
        "warnings": warnings,
        "note": "key material is never returned",
    }))
}

/// Runs `knx_export`: the result, or the refusal, as JSON.
fn export_file(dir: &Path, args: &ExportArgs) -> Result<Value, Value> {
    let none = Collected::default();
    let out_path = args.out.as_deref().map(PathBuf::from);
    let needs_out =
        |what: &str| refused(format!("what: {what} needs out, the path to write"), &none);
    match args.what.as_str() {
        "bundle" => export_bundle(
            dir,
            out_path.as_deref(),
            args.include_history.unwrap_or(true),
        )
        .map_err(|reason| refused(reason, &none)),
        "groups" => {
            let out = out_path.ok_or_else(|| needs_out("groups"))?;
            let format = match args.format.as_deref().unwrap_or("ets-csv") {
                "ets-csv" | "csv" => GroupFormat::EtsCsv,
                "ets-xml" | "xml" => GroupFormat::EtsXml,
                other => {
                    return Err(refused(
                        format!("format {other:?} is not ets-csv or ets-xml"),
                        &none,
                    ));
                }
            };
            let count = export::groups(dir, format, &out)
                .map_err(|err| refused(error_chain(&err), &none))?;
            Ok(json!({
                "ok": true,
                "what": "groups",
                "path": out.display().to_string(),
                "count": count,
                "format": format.label(),
                "summary": format!(
                    "Wrote {count} group address(es) to {} ({}); in ETS: Group Addresses -> \
                     Import, then pick this file.",
                    out.display(),
                    format.label()
                ),
            }))
        }
        "doc" => {
            let out = out_path.ok_or_else(|| needs_out("doc"))?;
            if let Some(other) = args
                .format
                .as_deref()
                .filter(|f| !matches!(*f, "md" | "markdown"))
            {
                return Err(refused(
                    format!("format {other:?}: the documentation is Markdown (md) only"),
                    &none,
                ));
            }
            let files = export::doc(dir, &out).map_err(|err| refused(error_chain(&err), &none))?;
            Ok(json!({
                "ok": true,
                "what": "doc",
                "path": out.display().to_string(),
                "files": files,
                "summary": format!(
                    "Wrote {} documentation file(s) to {}: {}.",
                    files.len(),
                    out.display(),
                    files.join(", ")
                ),
            }))
        }
        "keyring" => {
            let out = out_path.ok_or_else(|| needs_out("keyring"))?;
            export_keyring(dir, &out, args)
        }
        other => Err(refused(
            format!("what {other:?} is not bundle, groups, keyring or doc"),
            &none,
        )),
    }
}

/// Writes the bundle: the form `knx_export` and the `knx_export_bundle`
/// alias share.
///
/// # Errors
///
/// The refusal sentence.
pub(crate) fn export_bundle(
    dir: &Path,
    out: Option<&Path>,
    include_history: bool,
) -> Result<Value, String> {
    let (path, manifest) = export::bundle(dir, out, include_history)
        .map_err(|err| format!("the export failed: {}", error_chain(&err)))?;
    let summary = format!(
        "Wrote the bundle {}: {} device(s), {} group address(es), {} history snapshot(s); it \
         never contains vendor product data, keyrings or passwords.",
        path.display(),
        manifest.devices,
        manifest.group_addresses,
        manifest.history_snapshots
    );
    Ok(json!({
        "ok": true,
        "what": "bundle",
        "path": path.display().to_string(),
        "summary": summary,
        "manifest": manifest,
    }))
}

/// Writes the keyring, as `bussard keys export`.
fn export_keyring(dir: &Path, out: &Path, args: &ExportArgs) -> Result<Value, Value> {
    let none = Collected::default();
    let Some(password) = password(args.password.as_ref(), KEYRING_PASSWORD_ENV) else {
        return Err(refused(
            "the keyring export needs the key store password: ask the human and pass it as \
             password (it is never echoed or stored)",
            &none,
        ));
    };
    let mut log = Collected::default();
    let export =
        keyring::export_keyring(dir, out, &password, args.force.unwrap_or(false), &mut log)
            .map_err(|err| {
                refused(
                    error_chain(&err).replace("pass --force", "pass force: true"),
                    &none,
                )
            })?;
    let summary = if export.verified {
        format!(
            "Wrote {}: {} device(s), {} group key(s), {} interface(s), read back and verified; \
             keep it out of git.",
            out.display(),
            export.devices,
            export.group_keys,
            export.interfaces
        )
    } else {
        format!(
            "Wrote {}, but it does not carry the key store's keys: do not hand it on.",
            out.display()
        )
    };
    Ok(json!({
        "ok": export.verified,
        "what": "keyring",
        "path": out.display().to_string(),
        "summary": summary,
        "devices": export.devices,
        "group_keys": export.group_keys,
        "interfaces": export.interfaces,
        "skipped_devices": export.skipped_devices,
        "verified": export.verified,
        "group_addresses": export.group_addresses,
        "omitted_group_addresses": export.omitted_group_addresses,
        "leftovers": export.leftovers,
        "warnings": log.lines,
        "note": "key material is never returned",
    }))
}

/// The file name of `path`, or the path when it has none.
fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// The collected lines trimmed, without the blank ones: the `sentences` of
/// a result.
fn sentences(out: &Collected) -> Vec<String> {
    out.lines
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// A refusal with what the flow said before it stopped.
fn refused(reason: impl Into<String>, out: &Collected) -> Value {
    json!({
        "ok": false,
        "refused": true,
        "reason": reason.into(),
        "sentences": sentences(out),
    })
}

/// A structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A refusal, reported as a normal (structured) result the caller reads out.
fn refusal(reason: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    ok(refused(reason, &Collected::default()))
}
