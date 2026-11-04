//! Local enrolment mode (issue #732): the enrolment page of `web/enroll/`
//! and the relay API of [`crate::enroll_relay`] on one loopback origin, for
//! a desktop browser on the machine bussard runs on.
//!
//! The page and the relay share the origin, so the link carries no `r` and
//! the page's `connect-src 'self'` covers the relay. The page's files are
//! embedded at build time; nothing is read from disk at run time.
//!
//! [`LocalEnrollServer`] owns its own thread and runtime, so a synchronous
//! caller (`bussard keys enroll --local`) and an async one (the MCP server)
//! start it the same way. Dropping it stops the server.
//!
//! Requests whose `Host` is not this server's loopback address are refused
//! (`421`), so a web page that rebinds a DNS name to 127.0.0.1 cannot reach
//! it under its own origin.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use tokio::sync::oneshot;

use crate::enroll_relay::EnrollRelay;

/// The path the page is served under.
pub const PAGE_PATH: &str = "/enroll/";

/// How long [`LocalEnrollServer::finish`] keeps serving after the session
/// ended: the relay wakes a page's open long poll on the `DELETE`, so the
/// page reads `closed` within this.
pub const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// The response headers of the page itself. The policy repeats the page's
/// own `<meta>` policy with the network narrowed to this origin.
const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; media-src 'self' blob: mediastream:; connect-src 'self'; \
    base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

/// The page's files under [`PAGE_PATH`], embedded from `web/enroll/`.
fn page_file(path: &str) -> Option<(&'static [u8], &'static str)> {
    Some(match path {
        "" | "index.html" => (include_bytes!("../../../web/enroll/index.html"), HTML),
        "app.js" => (include_bytes!("../../../web/enroll/app.js"), JS),
        "enroll.js" => (include_bytes!("../../../web/enroll/enroll.js"), JS),
        "phonekey.js" => (include_bytes!("../../../web/enroll/phonekey.js"), JS),
        "style.css" => (include_bytes!("../../../web/enroll/style.css"), CSS),
        "ui.js" => (include_bytes!("../../../web/enroll/ui.js"), JS),
        "vendor/jsQR.js" => (include_bytes!("../../../web/enroll/vendor/jsQR.js"), JS),
        _ => return None,
    })
}

/// The page and `relay` on one origin. `allowed_hosts` are the `Host`
/// header values the server answers.
pub fn router(relay: &EnrollRelay, allowed_hosts: Vec<String>) -> Router {
    Router::new()
        .route("/enroll", get(|| async { Redirect::permanent(PAGE_PATH) }))
        .route("/enroll/", get(|| serve_file(String::new())))
        .route(
            "/enroll/{*path}",
            get(|axum::extract::Path(path): axum::extract::Path<String>| serve_file(path)),
        )
        .merge(relay.router())
        .layer(middleware::from_fn_with_state(
            std::sync::Arc::new(allowed_hosts),
            check_host,
        ))
}

async fn serve_file(path: String) -> Response {
    let Some((body, content_type)) = page_file(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if content_type == HTML {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(PAGE_CSP),
        );
    }
    response
}

/// Refuses a request whose `Host` is not one of this server's names.
pub(crate) async fn check_host(
    State(allowed): State<std::sync::Arc<Vec<String>>>,
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

/// The page and the relay served on `127.0.0.1` at a free port, until
/// dropped.
#[derive(Debug)]
pub struct LocalEnrollServer {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl LocalEnrollServer {
    /// Binds `127.0.0.1` at a free port and serves the page and a fresh
    /// relay on it.
    ///
    /// # Errors
    ///
    /// The socket cannot be bound or the server thread cannot start.
    pub fn start() -> std::io::Result<Self> {
        Self::start_with(EnrollRelay::new())
    }

    /// [`LocalEnrollServer::start`] over a given relay (the tests shorten
    /// its session lifetime).
    ///
    /// # Errors
    ///
    /// The socket cannot be bound or the server thread cannot start.
    pub fn start_with(relay: EnrollRelay) -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let port = addr.port();
        let app = router(
            &relay,
            vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")],
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (shutdown, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("enroll-local".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                        return;
                    };
                    // Not a graceful shutdown: an open long poll would hold
                    // it for up to 25 seconds. Dropping the runtime ends the
                    // connections.
                    tokio::select! {
                        _ = axum::serve(listener, app) => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(LocalEnrollServer {
            addr,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    /// The loopback address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The relay base URL, `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn relay_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The page URL, `http://127.0.0.1:<port>/enroll/`. A link to it needs
    /// no `r`: the relay is on the page's origin.
    #[must_use]
    pub fn page_url(&self) -> String {
        format!("http://{}{PAGE_PATH}", self.addr)
    }

    /// Keeps serving for [`CLOSE_GRACE`] so the page sees the session
    /// closed, then stops.
    pub fn finish(self) {
        std::thread::sleep(CLOSE_GRACE);
        drop(self);
    }
}

impl Drop for LocalEnrollServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_page_file_serves_every_page_file() {
        for path in [
            "",
            "app.js",
            "enroll.js",
            "phonekey.js",
            "style.css",
            "ui.js",
            "vendor/jsQR.js",
        ] {
            assert!(
                page_file(path).is_some_and(|(b, _)| !b.is_empty()),
                "{path}"
            );
        }
        assert!(page_file("../Cargo.toml").is_none());
        assert!(page_file("vendor/jsQR.LICENSE").is_none());
    }

    #[test]
    fn test_page_file_index_connects_to_self_only() -> TestResult {
        let (index, _) = page_file("").ok_or("no index")?;
        let index = std::str::from_utf8(index)?;
        let csp = index
            .lines()
            .find(|l| l.contains("Content-Security-Policy"))
            .ok_or("the page has no CSP")?;
        let connect = csp
            .split(';')
            .find(|d| d.trim().starts_with("connect-src"))
            .ok_or("no connect-src")?;
        // The page is served by its relay (the hosted Worker or this local
        // server), so it reaches its own origin and nothing else (#797).
        let sources: Vec<&str> = connect.split_whitespace().skip(1).collect();
        assert_eq!(sources, ["'self'"], "{connect}");
        Ok(())
    }

    #[test]
    fn test_local_enroll_server_serves_page_and_relay() -> TestResult {
        let server = LocalEnrollServer::start()?;
        let page = ureq::get(&server.page_url()).call()?;
        assert_eq!(page.content_type(), "text/html");
        let csp = page
            .header("content-security-policy")
            .ok_or("no CSP header")?
            .to_string();
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        assert!(page.into_string()?.contains("app.js"));
        let script = ureq::get(&format!("{}app.js", server.page_url())).call()?;
        assert_eq!(script.content_type(), "text/javascript");
        // The relay answers on the same origin.
        let sid = "AAAAAAAAAAAAAAAAAAAAAA";
        let created = ureq::put(&format!("{}/v1/sessions/{sid}", server.relay_url()))
            .set("Authorization", "Bearer t")
            .send_string("{}")?;
        assert_eq!(created.status(), 201);
        Ok(())
    }

    #[test]
    fn test_local_enroll_server_refuses_foreign_host() -> TestResult {
        let server = LocalEnrollServer::start()?;
        match ureq::get(&server.page_url())
            .set("Host", "attacker.example")
            .call()
        {
            Err(ureq::Error::Status(421, _)) => Ok(()),
            other => Err(format!("expected 421, got {other:?}").into()),
        }
    }
}
