//! The project password form (issue #818): a one-field page bussard serves
//! on the computer it runs on when an MCP tool needs the ETS project
//! password and the chat client can show a URL (URL-mode elicitation). The
//! human types the password into this page, never into the chat, so it
//! never passes through the assistant.
//!
//! The page binds `127.0.0.1` on a free port and answers only under a
//! random 128-bit token path, only to the exact `Host` it was opened under
//! (`127.0.0.1:<port>`), with no CORS headers. A post whose `Origin` is
//! another site is refused. The page has no script and makes no
//! third-party request; its files are embedded from `web/password/`.
//!
//! Each post becomes a [`Submission`] on the channel the caller gave
//! [`PasswordPage::start`]; the page waits for the caller's [`Verdict`] and
//! renders it: a wrong password shows the form again with the tries left,
//! an accepted or failed one closes the page for good (single use).

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Form, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bussard_secure::Password;
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};

/// How long [`PasswordPage::finish`] keeps serving after the last verdict,
/// so the browser receives the final page.
pub const FINISH_GRACE: Duration = Duration::from_secs(2);

/// The largest form body the page accepts.
const BODY_LIMIT: usize = 8 * 1024;

/// The response headers of the page: its own stylesheet only, posts to
/// itself only, no framing.
const PAGE_CSP: &str = "default-src 'none'; style-src 'self'; base-uri 'none'; \
    form-action 'self'; frame-ancestors 'none'; object-src 'none'";

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

const TEMPLATE: &str = include_str!("../../../web/password/index.html");
const STYLE: &str = include_str!("../../../web/password/password.css");

/// One password the human posted, with the channel the caller answers on.
pub struct Submission {
    /// The password as typed.
    pub password: Password,
    /// Where the caller sends its [`Verdict`]; dropping it closes the page.
    pub reply: oneshot::Sender<Verdict>,
}

impl std::fmt::Debug for Submission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Submission").finish_non_exhaustive()
    }
}

/// What the caller made of a [`Submission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The password does not open the project: the form again.
    Wrong {
        /// How many more tries the page accepts.
        tries_left: u32,
    },
    /// The password opened the project; `message` says what bussard did.
    /// The page closes.
    Accepted {
        /// The sentence the page shows.
        message: String,
    },
    /// The page closes without success; `message` says why.
    Closed {
        /// The sentence the page shows.
        message: String,
    },
}

/// What the page asks for.
#[derive(Debug, Clone, Default)]
pub struct PasswordPrompt {
    /// The ETS export the password is for (its file name), when known.
    pub file: Option<String>,
}

/// The password form served on `127.0.0.1` at a free port, until dropped.
pub struct PasswordPage {
    addr: SocketAddr,
    token: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for PasswordPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordPage")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// What the request handlers share.
struct Shared {
    prompt: PasswordPrompt,
    submissions: mpsc::Sender<Submission>,
    /// The page took its last verdict.
    closed: AtomicBool,
    /// The `Origin` a post from this page carries.
    origin: String,
}

/// The posted form.
#[derive(Deserialize)]
struct PostedForm {
    #[serde(default)]
    password: String,
}

impl PasswordPage {
    /// Binds `127.0.0.1` at a free port under a fresh random token and
    /// serves the form of `prompt`. Every post goes to `submissions`.
    ///
    /// # Errors
    ///
    /// No randomness, the socket cannot be bound or the server thread
    /// cannot start.
    pub fn start(
        prompt: PasswordPrompt,
        submissions: mpsc::Sender<Submission>,
    ) -> std::io::Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let host = format!("127.0.0.1:{}", addr.port());
        let app = router(
            &token,
            Shared {
                prompt,
                submissions,
                closed: AtomicBool::new(false),
                origin: format!("http://{host}"),
            },
            vec![host],
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (shutdown, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("password-page".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                        return;
                    };
                    tokio::select! {
                        _ = axum::serve(listener, app) => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(PasswordPage {
            addr,
            token,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    /// The page URL, `http://127.0.0.1:<port>/<token>/`. Never put it in a
    /// tool result.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/{}/", self.addr, self.token)
    }

    /// The loopback address the page listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Keeps serving for [`FINISH_GRACE`] so the browser gets the last
    /// page, then stops.
    pub fn finish(self) {
        std::thread::sleep(FINISH_GRACE);
        drop(self);
    }
}

impl Drop for PasswordPage {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The page's routes under `/<token>/`, behind the exact-`Host` check.
/// Every other path is a 404.
fn router(token: &str, shared: Shared, allowed_hosts: Vec<String>) -> Router {
    Router::new()
        .route(&format!("/{token}/"), get(page).post(post))
        .route(
            &format!("/{token}/password.css"),
            get(|| async { respond(StatusCode::OK, STYLE.to_string(), CSS) }),
        )
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(Arc::new(shared))
        .layer(middleware::from_fn_with_state(
            Arc::new(allowed_hosts),
            crate::enroll_local::check_host,
        ))
}

async fn page(State(shared): State<Arc<Shared>>) -> Response {
    if shared.closed.load(Ordering::SeqCst) {
        return html(&render_closed(
            "This form is closed. Go back to the chat.",
            false,
        ));
    }
    html(&render_form(&shared.prompt, None))
}

async fn post(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<PostedForm>,
) -> Response {
    // A browser always sends `Origin` on a post; another site's is refused.
    let origin = headers.get(header::ORIGIN).and_then(|o| o.to_str().ok());
    if origin.is_some_and(|o| o != shared.origin) {
        return respond(StatusCode::FORBIDDEN, "cross-origin post".to_string(), HTML);
    }
    if shared.closed.load(Ordering::SeqCst) {
        return html(&render_closed(
            "This form is closed. Go back to the chat.",
            false,
        ));
    }
    let password = Password::new(form.password);
    if password.is_empty() {
        return html(&render_form(
            &shared.prompt,
            Some("Enter the password.".to_string()),
        ));
    }
    let (reply, verdict) = oneshot::channel();
    if shared
        .submissions
        .send(Submission { password, reply })
        .await
        .is_err()
    {
        shared.closed.store(true, Ordering::SeqCst);
        return html(&render_closed(
            "This form is closed. Go back to the chat.",
            false,
        ));
    }
    match verdict.await {
        Ok(Verdict::Wrong { tries_left }) => html(&render_form(
            &shared.prompt,
            Some(format!(
                "That password does not open the project. Try again ({tries_left} {} left).",
                if tries_left == 1 { "try" } else { "tries" }
            )),
        )),
        Ok(Verdict::Accepted { message }) => {
            shared.closed.store(true, Ordering::SeqCst);
            html(&render_closed(&message, true))
        }
        Ok(Verdict::Closed { message }) => {
            shared.closed.store(true, Ordering::SeqCst);
            html(&render_closed(&message, false))
        }
        Err(_) => {
            shared.closed.store(true, Ordering::SeqCst);
            html(&render_closed(
                "This form is closed. Go back to the chat.",
                false,
            ))
        }
    }
}

/// An HTML page with the headers every answer carries.
fn html(body: &str) -> Response {
    respond(StatusCode::OK, body.to_string(), HTML)
}

/// `body` with its content type and the headers every answer carries.
fn respond(status: StatusCode, body: String, content_type: &'static str) -> Response {
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // `same-origin`, not `no-referrer`: a post then carries this page's
    // `Origin` (a `no-referrer` page posts `Origin: null`).
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    if content_type == HTML {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(PAGE_CSP),
        );
    }
    response
}

/// The form, with `problem` above it when the last post had one.
fn render_form(prompt: &PasswordPrompt, problem: Option<String>) -> String {
    let what = match &prompt.file {
        Some(file) => format!("<strong>{}</strong>", escape_html(file)),
        None => "your ETS project export".to_string(),
    };
    let mut message = format!(
        "<h1>Enter the project password</h1><p>bussard needs the password of {what} to \
         import it. It stores the password in the <code>.env</code> file next to your \
         project folder, so you do not have to enter it again.</p>"
    );
    if let Some(problem) = problem {
        message = format!(
            "<div class=\"banner bad\" role=\"alert\">{}</div>{message}",
            escape_html(&problem)
        );
    }
    let form = "<form method=\"post\" action=\"./\">\
        <label for=\"password\">Project password</label>\
        <input id=\"password\" name=\"password\" type=\"password\" \
        autocomplete=\"current-password\" required autofocus>\
        <button type=\"submit\">Import the project</button></form>";
    TEMPLATE
        .replace("{{message}}", &message)
        .replace("{{form}}", form)
}

/// The closed page with `message`.
fn render_closed(message: &str, good: bool) -> String {
    let tone = if good { "good" } else { "bad" };
    TEMPLATE
        .replace(
            "{{message}}",
            &format!(
                "<div class=\"banner {tone}\" role=\"status\">{}</div>",
                escape_html(message)
            ),
        )
        .replace("{{form}}", "<p>You can close this page.</p>")
}

/// `text` safe inside an HTML element or a double-quoted attribute.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A page whose caller answers every post with the next of `verdicts`
    /// and records the passwords it got.
    fn start(
        verdicts: Vec<Verdict>,
    ) -> Result<(PasswordPage, std::sync::mpsc::Receiver<String>), Box<dyn std::error::Error>> {
        let (submissions, mut incoming) = mpsc::channel::<Submission>(1);
        let (seen_tx, seen) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut verdicts = verdicts.into_iter();
            while let Some(submission) = incoming.blocking_recv() {
                let _ = seen_tx.send(submission.password.expose().to_string());
                match verdicts.next() {
                    Some(verdict) => {
                        let _ = submission.reply.send(verdict);
                    }
                    None => return,
                }
            }
        });
        let page = PasswordPage::start(
            PasswordPrompt {
                file: Some("Home <1>.knxproj".to_string()),
            },
            submissions,
        )?;
        Ok((page, seen))
    }

    fn post_password(url: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        Ok(ureq::post(url)
            .send_form(&[("password", password)])?
            .into_string()?)
    }

    #[test]
    fn test_password_page_serves_the_form_under_token() -> TestResult {
        let (page, _seen) = start(Vec::new())?;
        let url = page.url();
        let token = url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .ok_or("no token")?;
        assert_eq!(token.len(), 32, "128 bits as hex: {url}");
        let response = ureq::get(&url).call()?;
        let csp = response
            .header("content-security-policy")
            .ok_or("no CSP")?
            .to_string();
        assert!(csp.contains("form-action 'self'"), "{csp}");
        assert!(!csp.contains("script-src"), "{csp}");
        assert!(response.header("access-control-allow-origin").is_none());
        let body = response.into_string()?;
        assert!(body.contains("Home &lt;1&gt;.knxproj"), "{body}");
        assert!(body.contains("type=\"password\""));
        assert!(!body.contains("{{"), "a placeholder is left");
        assert!(!body.contains("<script"), "no script");
        assert_eq!(
            ureq::get(&format!("{url}password.css")).call()?.status(),
            200
        );
        Ok(())
    }

    #[test]
    fn test_password_page_wrong_then_accepted_closes() -> TestResult {
        let (page, seen) = start(vec![
            Verdict::Wrong { tries_left: 2 },
            Verdict::Accepted {
                message: "Stored.".to_string(),
            },
        ])?;
        let url = page.url();
        let wrong = post_password(&url, "nope")?;
        assert!(wrong.contains("2 tries left"), "{wrong}");
        assert!(wrong.contains("type=\"password\""), "the form again");
        assert!(!wrong.contains("nope"), "the page never echoes a password");
        let done = post_password(&url, "right")?;
        assert!(done.contains("Stored."), "{done}");
        assert!(!done.contains("type=\"password\""), "no form any more");
        assert_eq!(seen.recv()?, "nope");
        assert_eq!(seen.recv()?, "right");
        // Single use: the page stays closed and forwards nothing more.
        let again = post_password(&url, "more")?;
        assert!(again.contains("closed"), "{again}");
        assert!(ureq::get(&url).call()?.into_string()?.contains("closed"));
        assert!(seen.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn test_password_page_empty_password_is_not_forwarded() -> TestResult {
        let (page, seen) = start(Vec::new())?;
        let body = post_password(&page.url(), "")?;
        assert!(body.contains("Enter the password."), "{body}");
        assert!(seen.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn test_password_page_refuses_cross_origin_post() -> TestResult {
        let (page, seen) = start(Vec::new())?;
        match ureq::post(&page.url())
            .set("Origin", "https://attacker.example")
            .send_form(&[("password", "x")])
        {
            Err(ureq::Error::Status(403, _)) => {}
            other => return Err(format!("expected 403, got {other:?}").into()),
        }
        assert!(seen.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn test_password_page_refuses_other_hosts_and_paths() -> TestResult {
        let (page, _seen) = start(Vec::new())?;
        match ureq::get(&page.url())
            .set("Host", "attacker.example")
            .call()
        {
            Err(ureq::Error::Status(421, _)) => {}
            other => return Err(format!("expected 421, got {other:?}").into()),
        }
        let root = format!("http://{}/", page.addr());
        match ureq::get(&root).call() {
            Err(ureq::Error::Status(404, _)) => Ok(()),
            other => Err(format!("expected 404, got {other:?}").into()),
        }
    }
}
