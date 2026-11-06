//! Local enrolment mode (issue #732): the enrolment page of `web/enroll/`
//! and the relay API of [`crate::enroll_relay`] on one loopback origin, for
//! a desktop browser on the machine bussard runs on.
//!
//! The page and the relay share the origin, so the link carries no `r` and
//! the page's `connect-src 'self'` covers the relay. The page's files are
//! embedded at build time; nothing is read from disk at run time.
//!
//! [`LocalEnrollServer`] is a [`LocalServer`]: its own thread and runtime,
//! stopped when dropped, and requests whose `Host` is not this server's
//! loopback address are refused (`421`).

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

use crate::enroll_relay::EnrollRelay;
use crate::local_server::{self, CSS, HTML, JS, LocalServer, Policy};

/// The path the page is served under.
pub const PAGE_PATH: &str = "/enroll/";

/// How long [`LocalEnrollServer::finish`] keeps serving after the session
/// ended: the relay wakes a page's open long poll on the `DELETE`, so the
/// page reads `closed` within this.
pub const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// The headers of the page itself. The policy repeats the page's own
/// `<meta>` policy with the network narrowed to this origin.
const POLICY: Policy = Policy {
    csp: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
        media-src 'self' blob: mediastream:; connect-src 'self'; base-uri 'none'; \
        form-action 'none'; frame-ancestors 'none'; object-src 'none'",
    referrer: "no-referrer",
};

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
    let routes = Router::new()
        .route("/enroll", get(|| async { Redirect::permanent(PAGE_PATH) }))
        .route("/enroll/", get(|| serve_file(String::new())))
        .route(
            "/enroll/{*path}",
            get(|axum::extract::Path(path): axum::extract::Path<String>| serve_file(path)),
        )
        .merge(relay.router());
    local_server::only_hosts(routes, allowed_hosts)
}

async fn serve_file(path: String) -> Response {
    match page_file(&path) {
        Some((body, content_type)) => POLICY.file(body, content_type),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The page and the relay served on `127.0.0.1` at a free port, until
/// dropped.
#[derive(Debug)]
pub struct LocalEnrollServer(LocalServer);

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
        LocalServer::start("enroll-local", CLOSE_GRACE, |addr: SocketAddr| {
            let port = addr.port();
            router(
                &relay,
                vec![local_server::host(addr), format!("localhost:{port}")],
            )
        })
        .map(LocalEnrollServer)
    }

    /// The loopback address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.0.addr()
    }

    /// The relay base URL, `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.0.url("")
    }

    /// The page URL, `http://127.0.0.1:<port>/enroll/`. A link to it needs
    /// no `r`: the relay is on the page's origin.
    #[must_use]
    pub fn page_url(&self) -> String {
        self.0.url(PAGE_PATH)
    }

    /// Keeps serving for [`CLOSE_GRACE`] so the page sees the session
    /// closed, then stops.
    pub fn finish(self) {
        self.0.finish();
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
