//! The loopback server behind bussard's own pages (issue #911): the pairing
//! page ([`crate::pairing_page`]), the project password form
//! ([`crate::password_page`]) and local enrolment
//! ([`crate::enroll_local`]).
//!
//! [`LocalServer`] binds `127.0.0.1` on a free port and serves a router on a
//! named thread with its own current-thread runtime, so a synchronous caller
//! (`bussard keys enroll --local`) and an async one (the MCP server) start it
//! the same way. Dropping it stops the server.
//!
//! [`only_hosts`] refuses a request whose `Host` is not one of the server's
//! names (`421`), so a web page that rebinds a DNS name to 127.0.0.1 cannot
//! reach it under its own origin. [`Policy`] holds the headers every answer
//! carries and fills the page shell `web/page.html` that the pairing page and
//! the password form share.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tokio::sync::oneshot;

/// The content type of an HTML answer.
pub(crate) const HTML: &str = "text/html; charset=utf-8";
/// The content type of a script.
pub(crate) const JS: &str = "text/javascript; charset=utf-8";
/// The content type of a stylesheet.
pub(crate) const CSS: &str = "text/css; charset=utf-8";
/// The content type of a JSON answer.
pub(crate) const JSON: &str = "application/json";

/// The shell of the pairing page and the password form.
const SHELL: &str = include_str!("../../../web/page.html");

/// A router served on `127.0.0.1` at a free port, until dropped.
#[derive(Debug)]
pub struct LocalServer {
    addr: SocketAddr,
    grace: Duration,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl LocalServer {
    /// Binds `127.0.0.1` at a free port and serves the router `router`
    /// builds for that address, on a thread called `name`.
    /// [`LocalServer::finish`] keeps serving for `grace` first.
    ///
    /// # Errors
    ///
    /// The socket cannot be bound or the server thread cannot start.
    pub fn start(
        name: &str,
        grace: Duration,
        router: impl FnOnce(SocketAddr) -> Router,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let app = router(addr);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (shutdown, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                        return;
                    };
                    // Not graceful: an open long poll would hold the
                    // shutdown. Dropping the runtime ends the connections.
                    tokio::select! {
                        _ = axum::serve(listener, app) => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(LocalServer {
            addr,
            grace,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    /// The loopback address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>` followed by `path`.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Keeps serving for the grace period so a page sees the end, then
    /// stops.
    pub fn finish(self) {
        std::thread::sleep(self.grace);
        drop(self);
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `host:port` of `addr` as a `Host` header names it.
#[must_use]
pub(crate) fn host(addr: SocketAddr) -> String {
    format!("127.0.0.1:{}", addr.port())
}

/// A fresh random 128-bit token, hex: the path a page is served under.
pub(crate) fn token() -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(bussard_model::text::hex(&bytes))
}

/// `router` behind the exact-`Host` check: only `hosts` are answered.
pub(crate) fn only_hosts(router: Router, hosts: Vec<String>) -> Router {
    router.layer(middleware::from_fn_with_state(Arc::new(hosts), check_host))
}

/// Refuses a request whose `Host` is not one of this server's names.
async fn check_host(
    State(allowed): State<Arc<Vec<String>>>,
    request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    if host.is_some_and(|h| allowed.iter().any(|a| a.eq_ignore_ascii_case(h))) {
        next.run(request).await
    } else {
        (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response()
    }
}

/// What a page sends with every answer, and what its shell says.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Policy {
    /// The `Content-Security-Policy` of an HTML answer.
    pub csp: &'static str,
    /// The `Referrer-Policy` of every answer.
    pub referrer: &'static str,
}

impl Policy {
    /// `body` with `status`, its content type and the headers every answer
    /// carries.
    pub(crate) fn respond(
        &self,
        status: StatusCode,
        body: impl IntoResponse,
        content_type: &'static str,
    ) -> Response {
        let mut response = (status, body).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static(self.referrer),
        );
        if content_type == HTML {
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(self.csp),
            );
        }
        response
    }

    /// `body` as a `200` answer of `content_type`.
    pub(crate) fn file(&self, body: impl IntoResponse, content_type: &'static str) -> Response {
        self.respond(StatusCode::OK, body, content_type)
    }

    /// An HTML page as a `200` answer.
    pub(crate) fn html(&self, page: String) -> Response {
        self.file(page, HTML)
    }

    /// The shared shell around `body`: the page titled `title`, with its
    /// stylesheet `style`, its module script `script` if any, and `class` on
    /// `<body>`. The `<meta>` policy repeats the header one without
    /// `frame-ancestors`, which a `<meta>` policy cannot carry.
    pub(crate) fn page(
        &self,
        title: &str,
        style: &str,
        script: Option<&str>,
        class: &str,
        body: &str,
    ) -> String {
        let script = script.map_or(String::new(), |src| {
            format!("\n  <script type=\"module\" src=\"{src}\"></script>")
        });
        SHELL
            .replace("{{csp}}", &self.csp.replace(" frame-ancestors 'none';", ""))
            .replace("{{referrer}}", self.referrer)
            .replace("{{title}}", title)
            .replace("{{style}}", style)
            .replace("{{script}}", &script)
            .replace("{{class}}", class)
            .replace("{{body}}", body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const POLICY: Policy = Policy {
        csp: "default-src 'none'; frame-ancestors 'none'; object-src 'none'",
        referrer: "no-referrer",
    };

    #[test]
    fn test_page_fills_every_placeholder() {
        let page = POLICY.page("a title", "a.css", Some("a.js"), "c", "<p>body</p>");
        assert!(page.contains("<title>bussard: a title</title>"), "{page}");
        assert!(page.contains("content=\"default-src 'none'; object-src 'none'\""));
        assert!(page.contains("<script type=\"module\" src=\"a.js\"></script>"));
        assert!(page.contains("<body class=\"c\">"));
        assert!(page.contains("<p>body</p>"));
        assert!(!page.contains("{{"), "a placeholder is left: {page}");
        let page = POLICY.page("t", "a.css", None, "", "");
        assert!(!page.contains("<script"), "{page}");
    }

    #[test]
    fn test_local_server_serves_and_checks_host() -> TestResult {
        let server = LocalServer::start("local-server-test", Duration::ZERO, |addr| {
            only_hosts(
                Router::new().route("/x", get(|| async { POLICY.html("hi".to_string()) })),
                vec![host(addr)],
            )
        })?;
        let response = ureq::get(&server.url("/x")).call()?;
        assert_eq!(response.header("referrer-policy"), Some("no-referrer"));
        assert!(response.header("content-security-policy").is_some());
        assert_eq!(response.into_string()?, "hi");
        match ureq::get(&server.url("/x"))
            .set("Host", "attacker.example")
            .call()
        {
            Err(ureq::Error::Status(421, _)) => {}
            other => return Err(format!("expected 421, got {other:?}").into()),
        }
        server.finish();
        Ok(())
    }
}
