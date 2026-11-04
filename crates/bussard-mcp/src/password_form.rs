//! The project password from a browser form (issue #818), for `knx_setup`
//! and `knx_import_file`.
//!
//! When the import of a password-protected `.knxproj` finds no password
//! (no `password` argument, no `BUSSARD_PROJECT_PASSWORD`) and the client
//! declares URL-mode elicitation, the tool serves a one-field form on
//! 127.0.0.1 ([`bussard_viz::password_page`]) and hands its URL to the
//! client by URL-mode elicitation, exactly as `knx_enroll_certificates`
//! hands over its pairing page (#798): the in-call `elicitation/create`,
//! or from protocol 2026-07-28 an `InputRequiredResult` the client answers
//! by calling the tool again (multi round-trip). The human types the
//! password into the form; the tool tries it with the import itself, says
//! on the page when it is wrong (at most [`MAX_TRIES`] times), and once it
//! opens the project stores it as `BUSSARD_PROJECT_PASSWORD` in the `.env`
//! the server reads ([`bussard_model::dotenv::store_target`]).
//!
//! The password never reaches the assistant: no tool result, log line,
//! `Debug` output or error message holds it, and neither the page's URL
//! nor its token appears in a result. Without URL-mode elicitation the
//! tools refuse as before.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bussard_secure::Password;
use bussard_viz::password_page::{PasswordPage, PasswordPrompt, Submission, Verdict};
use rmcp::RoleServer;
use rmcp::model::{
    CallToolResponse, CallToolResult, ElicitRequest, ElicitRequestParams, ElicitResult,
    ElicitationAction, InputRequest, InputRequests, InputRequiredResult, ProtocolVersion,
};
use rmcp::service::RequestContext;
use serde_json::json;
use tokio::sync::mpsc;

/// How long a form waits for the password before the tool gives up.
pub const FORM_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// How many passwords one form tries.
pub const MAX_TRIES: u32 = 5;

/// The `requestState` prefix of a multi round-trip call; the rest is the
/// form's elicitation id.
const REQUEST_STATE_PREFIX: &str = "project-password:";

/// The key of the elicitation in `InputRequiredResult.inputRequests`.
const INPUT_KEY: &str = "project_password";

/// The `.env` key the password is stored under.
const ENV_KEY: &str = bussard_service::setup::import::PROJECT_PASSWORD_ENV;

/// What the tool result says when the password came from the form.
pub const FROM_FORM: &str = "The project password was taken from the password form and stored \
    in .env.";

/// One open password form.
pub struct PendingForm {
    /// The elicitation id, the handle a multi round-trip call names it by.
    id: String,
    /// The page, until the form is done with.
    page: Mutex<Option<PasswordPage>>,
    /// The passwords the page receives.
    submissions: tokio::sync::Mutex<mpsc::Receiver<Submission>>,
}

impl std::fmt::Debug for PendingForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingForm").finish_non_exhaustive()
    }
}

impl PendingForm {
    /// Stops the page after the browser got its last answer.
    fn finish(&self) {
        if let Some(page) = lock(&self.page).take() {
            std::thread::spawn(move || page.finish());
        }
    }
}

/// The server's open password form: at most one, shared by every clone of
/// the handler.
#[derive(Debug, Clone, Default)]
pub struct PasswordForms(Arc<Mutex<Option<Arc<PendingForm>>>>);

impl PasswordForms {
    /// No form open.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the form `id` out, closing any other.
    fn take(&self, id: &str) -> Option<Arc<PendingForm>> {
        let form = lock(&self.0).take()?;
        if form.id == id {
            Some(form)
        } else {
            form.finish();
            None
        }
    }

    /// Makes `form` the open one, closing any earlier one. A form the
    /// client does not come back for closes after [`FORM_LIFETIME`].
    fn put(&self, form: Arc<PendingForm>) {
        let id = form.id.clone();
        if let Some(old) = lock(&self.0).replace(form) {
            old.finish();
        }
        let forms = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(FORM_LIFETIME).await;
            let mut open = lock(&forms.0);
            if open.as_ref().is_some_and(|form| form.id == id)
                && let Some(form) = open.take()
            {
                form.finish();
            }
        });
    }
}

/// A lock that survives a panicked holder.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Where a tool stands after asking for the form.
pub enum Step {
    /// The client cannot show a URL: refuse as before.
    Unsupported,
    /// Answer the call with this (an `InputRequiredResult`, a declined or a
    /// failed form).
    Answer(CallToolResponse),
    /// The human opened the form: collect the password.
    Open(Arc<PendingForm>),
}

impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Step::Unsupported => "Unsupported",
            Step::Answer(_) => "Answer",
            Step::Open(_) => "Open",
        })
    }
}

/// Whether the client of this call declared URL-mode elicitation.
pub fn shows_urls(context: &RequestContext<RoleServer>) -> bool {
    context
        .client_capabilities()
        .and_then(|caps| caps.elicitation)
        .is_some_and(|elicitation| elicitation.url.is_some())
}

/// A tool result that ends the call without an import.
pub fn not_imported(reason: &str, next_step: &str) -> CallToolResult {
    let mut result = CallToolResult::structured(json!({
        "ok": false,
        "done": false,
        "password_form": "closed",
        "error": reason,
        "summary": "Nothing was written.",
        "next_step": next_step,
    }));
    result.is_error = Some(true);
    result
}

/// What to tell the assistant when the form ended without a password.
const NEVER_IN_CHAT: &str = "Never ask the human for the project password in chat. Call the \
    tool again to show the password form once more, or ask the owner to put \
    BUSSARD_PROJECT_PASSWORD in the .env next to the model directory.";

/// Opens a password form for `file` and shows it to the human: the
/// elicitation of `context`'s protocol. `Unsupported` without URL-mode
/// elicitation.
pub async fn ask(
    forms: &PasswordForms,
    context: &RequestContext<RoleServer>,
    file: Option<String>,
) -> Step {
    if !shows_urls(context) {
        return Step::Unsupported;
    }
    let (sender, submissions) = mpsc::channel(1);
    let page = match PasswordPage::start(PasswordPrompt { file }, sender) {
        Ok(page) => page,
        Err(err) => {
            return Step::Answer(
                not_imported(&format!("starting the password form: {err}"), NEVER_IN_CHAT).into(),
            );
        }
    };
    let id = match new_id() {
        Ok(id) => id,
        Err(err) => return Step::Answer(not_imported(&err, NEVER_IN_CHAT).into()),
    };
    let params = ElicitRequestParams::UrlElicitationParams {
        meta: None,
        message: format!(
            "bussard asks you to open its password form, served by bussard on this computer \
             ({}). Enter the ETS project password there, not in the chat. bussard stores it in \
             the .env file next to your project folder.",
            page.addr()
        ),
        url: page.url(),
        elicitation_id: id.clone(),
    };
    let form = Arc::new(PendingForm {
        id: id.clone(),
        page: Mutex::new(Some(page)),
        submissions: tokio::sync::Mutex::new(submissions),
    });
    if context
        .protocol_version()
        .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28)
    {
        forms.put(form);
        let mut requests = InputRequests::new();
        requests.insert(
            INPUT_KEY.to_owned(),
            InputRequest::Elicitation(ElicitRequest::new(params)),
        );
        return Step::Answer(
            InputRequiredResult::new(Some(requests), Some(format!("{REQUEST_STATE_PREFIX}{id}")))
                .into(),
        );
    }
    match context.peer.create_elicitation(params).await {
        Ok(result) => after_elicitation(form, result.action),
        Err(err) => {
            // Logged only: a client's error text could echo the URL.
            tracing::warn!(%err, "password form: the client did not show the form");
            form.finish();
            Step::Answer(
                not_imported("the chat app did not show the password form", NEVER_IN_CHAT).into(),
            )
        }
    }
}

/// Whether `state` is the request state of a password form.
pub fn is_form_state(state: &str) -> bool {
    state.starts_with(REQUEST_STATE_PREFIX)
}

/// The second round of a multi round-trip call: `state` names the form,
/// `responses` holds the human's answer to the elicitation.
pub fn resume(
    forms: &PasswordForms,
    state: &str,
    responses: Option<&rmcp::model::InputResponses>,
) -> Step {
    let form = state
        .strip_prefix(REQUEST_STATE_PREFIX)
        .and_then(|id| forms.take(id));
    let Some(form) = form else {
        return Step::Answer(
            not_imported(
                "that password form is no longer open",
                "Call the tool again without the request state to show a new password form.",
            )
            .into(),
        );
    };
    let action = responses
        .and_then(|responses| responses.get(INPUT_KEY).cloned())
        .and_then(|value| serde_json::from_value::<ElicitResult>(value).ok())
        .map_or(ElicitationAction::Cancel, |answer| answer.action);
    after_elicitation(form, action)
}

/// The step once the human answered the elicitation of `form`.
fn after_elicitation(form: Arc<PendingForm>, action: ElicitationAction) -> Step {
    if action == ElicitationAction::Accept {
        return Step::Open(form);
    }
    form.finish();
    Step::Answer(
        not_imported(
            "the human did not open the password form",
            "The human declined or dismissed the password form. Never ask for the project \
             password in chat; call the tool again only if the human asks to.",
        )
        .into(),
    )
}

/// What one try of a password gave.
#[derive(Debug)]
pub enum Attempt<T> {
    /// The password opened the project; `T` is the tool's outcome.
    Opened(T),
    /// The password does not open the project.
    WrongPassword,
    /// The import failed for another reason; `T` is the tool's outcome.
    /// The password is not stored.
    Failed(T),
}

/// How collecting the password ended.
#[derive(Debug)]
pub enum Collected<T> {
    /// A password opened the project; `stored` is the `.env` it was stored
    /// in, or why storing failed.
    Opened {
        /// The tool's outcome.
        value: T,
        /// The `.env` file, or the reason it was not written.
        stored: Result<PathBuf, String>,
    },
    /// The import failed for another reason than the password.
    Failed(T),
    /// No password opened the project; the sentence says why.
    Ended(String),
}

/// Waits for passwords on `form` and tries each with `attempt` until one
/// opens the project, the human gave [`MAX_TRIES`] wrong ones, or
/// [`FORM_LIFETIME`] passed. A password that opens the project is stored
/// in the `.env` for `model_dir`; `done` says on the page what happened
/// next.
pub async fn collect<T, F, Fut>(
    form: Arc<PendingForm>,
    model_dir: &Path,
    done: &str,
    mut attempt: F,
) -> Collected<T>
where
    F: FnMut(Password) -> Fut,
    Fut: Future<Output = Attempt<T>>,
{
    let deadline = tokio::time::Instant::now() + FORM_LIFETIME;
    let mut submissions = form.submissions.lock().await;
    let mut tries = 0;
    let ended = loop {
        let submission = match tokio::time::timeout_at(deadline, submissions.recv()).await {
            Ok(Some(submission)) => submission,
            Ok(None) => break "the password form closed".to_string(),
            Err(_) => {
                break format!(
                    "nobody entered the password within {} minutes",
                    FORM_LIFETIME.as_secs() / 60
                );
            }
        };
        tries += 1;
        let password = submission.password.clone();
        match attempt(submission.password).await {
            Attempt::Opened(value) => {
                let stored = store_password(model_dir, &password);
                let message = match &stored {
                    Ok(path) => format!(
                        "The password opens the project. bussard stored it in {} and {done}. \
                         You can close this page and go back to the chat.",
                        path.display()
                    ),
                    Err(reason) => format!(
                        "The password opens the project and bussard {done}, but storing it in \
                         .env failed ({reason}). You can close this page and go back to the chat."
                    ),
                };
                let _ = submission.reply.send(Verdict::Accepted { message });
                drop(submissions);
                form.finish();
                return Collected::Opened { value, stored };
            }
            Attempt::Failed(value) => {
                let _ = submission.reply.send(Verdict::Closed {
                    message: "The import failed; the chat says why. You can close this page."
                        .to_string(),
                });
                drop(submissions);
                form.finish();
                return Collected::Failed(value);
            }
            Attempt::WrongPassword if tries < MAX_TRIES => {
                let _ = submission.reply.send(Verdict::Wrong {
                    tries_left: MAX_TRIES - tries,
                });
            }
            Attempt::WrongPassword => {
                let _ = submission.reply.send(Verdict::Closed {
                    message: format!(
                        "That password does not open the project either. After {MAX_TRIES} \
                         wrong passwords this form is closed; go back to the chat."
                    ),
                });
                break format!("{MAX_TRIES} wrong passwords were entered in the password form");
            }
        }
    };
    drop(submissions);
    form.finish();
    Collected::Ended(ended)
}

/// The sentence for the assistant when collecting ended without a password.
pub fn ended(reason: &str) -> CallToolResult {
    not_imported(&format!("{reason}; nothing was imported"), NEVER_IN_CHAT)
}

/// The sentence for the tool result once the password came from the form.
pub fn stored_note(stored: &Result<PathBuf, String>) -> String {
    match stored {
        Ok(_) => FROM_FORM.to_string(),
        Err(reason) => format!(
            "The project password was taken from the password form; storing it in .env failed \
             ({reason}), so the next import asks again."
        ),
    }
}

/// Stores `password` as `BUSSARD_PROJECT_PASSWORD` in the `.env` the server
/// reads for `model_dir`, and makes it this process's value too.
fn store_password(model_dir: &Path, password: &Password) -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let file = bussard_model::dotenv::store_target(model_dir, &cwd);
    bussard_model::dotenv::store(&file, ENV_KEY, password.expose()).map_err(|e| e.to_string())?;
    bussard_model::dotenv::remember(ENV_KEY, password.expose());
    tracing::info!("password form: stored {ENV_KEY} in {}", file.display());
    Ok(file)
}

/// A fresh random elicitation id.
fn new_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("drawing a random id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
