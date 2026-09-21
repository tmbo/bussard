//! The browser-facing request guard: `Host` allow-list and `Origin` check.
//!
//! `bussard viz` binds an unauthenticated HTTP port that can put telegrams on a
//! real KNX bus. Two browser attacks reach that port without the operator ever
//! visiting the page, and this middleware closes both.
//!
//! ## DNS rebinding (the `Host` allow-list)
//!
//! An attacker page on `evil.example` can make its own name resolve to
//! `127.0.0.1` a moment later, which makes the browser treat
//! `http://evil.example:8080/api/group-write` as **same-origin with the
//! attacker's page**: no CORS preflight, full read access to every response.
//! The one thing the attacker cannot change is the `Host` header the browser
//! sends, which still carries their name.
//!
//! So a request is accepted only when its `Host` is
//!
//! * a bare IP literal (`127.0.0.1:8080`, `[::1]:8080`, `192.0.2.10:8080`) —
//!   rebinding needs a *name*, so an IP `Host` cannot be forged this way;
//! * `localhost`, or any `*.localhost` name (RFC 6761 reserves those to
//!   loopback); or
//! * one of the extra names the operator allow-listed
//!   ([`Security::allowed_hosts`](crate::state::Security::allowed_hosts)).
//!
//! A request with **no** `Host` at all is accepted: HTTP/1.1 requires the
//! header and every browser sends it (HTTP/2 sends `:authority`, which hyper
//! puts in the URI), so a header-less request cannot come from the attack this
//! guards against — but it is what `curl --http1.0`, the handler unit tests and
//! monitoring probes send.
//!
//! ## Cross-site request forgery (the `Origin` check)
//!
//! Without rebinding, an attacker page can still *blind-fire* a request at
//! `127.0.0.1:8080`: a form POST, or a `fetch` with `mode: "no-cors"`. It
//! cannot read the response, but `POST /api/reload` and `POST /api/group-write`
//! have side effects, so that is enough. Browsers attach `Origin` to every
//! state-changing request, so any non-idempotent method whose `Origin` is not
//! itself an allowed host is refused. `Origin: null` (a sandboxed iframe or a
//! `file://` page) is refused too. A missing `Origin` is accepted for the same
//! reason a missing `Host` is: no browser omits it here.
//!
//! Both refusals are `403` with the API's standard error body, so the frontend
//! surfaces them like any other error.

use axum::extract::{Request, State};
use axum::http::{Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::state::AppState;

/// Rejects requests whose `Host` (or, for state-changing methods, `Origin`) is
/// not one this server answers to. See the module docs for the threat model.
pub async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let allowed = state.security.allowed_hosts.as_slice();

    // --- Host ------------------------------------------------------------
    // HTTP/2 carries the authority in the URI rather than a Host header.
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| request.uri().host().map(str::to_string));

    if let Some(host) = &host {
        if !host_allowed(host, allowed) {
            return refuse(format!(
                "refusing a request for Host {host:?}: bussard viz answers only to loopback names \
                 and IP literals. A different name here usually means DNS rebinding"
            ));
        }
    }

    // --- Origin (state-changing methods only) ----------------------------
    let state_changing = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if state_changing {
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let Some(origin) = origin {
            if !origin_allowed(&origin, allowed) {
                return refuse(format!(
                    "refusing a cross-origin {} from Origin {origin:?}",
                    request.method()
                ));
            }
        }
    }

    next.run(request).await
}

/// Builds the `403` body, matching the JSON API's error shape.
fn refuse(message: String) -> Response {
    tracing::warn!("{message}");
    ApiError::Forbidden(message).into_response()
}

/// Whether an `Origin` header value names an allowed host.
///
/// An origin is `scheme "://" host [ ":" port ]`, or the literal `null`. `null`
/// is always refused: it is what a sandboxed iframe or a `file://` page sends,
/// and neither has business writing to the bus.
fn origin_allowed(origin: &str, allowed: &[String]) -> bool {
    let rest = match origin.split_once("://") {
        Some((_scheme, rest)) => rest,
        // "null", or anything else that is not a serialized origin.
        None => return false,
    };
    !rest.is_empty() && host_allowed(rest, allowed)
}

/// Whether a `Host`-style `authority` (`host`, `host:port`, `[v6]:port`) is one
/// this server answers to. See the module docs.
fn host_allowed(authority: &str, allowed: &[String]) -> bool {
    let host = strip_port(authority).to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    // An IP literal cannot be produced by DNS rebinding.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // RFC 6761: `localhost` and any name under it always resolve to loopback.
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    allowed.iter().any(|a| a == &host)
}

/// Strips the port and the IPv6 brackets from an authority, leaving the host.
fn strip_port(authority: &str) -> &str {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]:8080` / `[::1]` — the host is what precedes the closing bracket.
        return match rest.split_once(']') {
            Some((host, _)) => host,
            None => rest,
        };
    }
    match authority.rsplit_once(':') {
        // A bare IPv6 address has several colons and no brackets; treat the
        // whole thing as the host rather than cutting it in half.
        Some((head, _)) if !head.contains(':') => head,
        _ => authority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<String> {
        vec!["viz.internal".to_string()]
    }

    #[test]
    fn test_host_allowed_accepts_loopback_and_ip_literals() {
        for host in [
            "127.0.0.1:8080",
            "127.0.0.1",
            "[::1]:8080",
            "::1",
            "localhost",
            "localhost:8080",
            "dev.localhost:8080",
            "192.0.2.10:8080",
        ] {
            assert!(host_allowed(host, &allowed()), "{host} must be allowed");
        }
    }

    #[test]
    fn test_host_allowed_rejects_foreign_names() {
        for host in [
            "evil.example",
            "evil.example:8080",
            "localhost.evil.example",
            "",
        ] {
            assert!(!host_allowed(host, &allowed()), "{host} must be refused");
        }
    }

    #[test]
    fn test_host_allowed_honours_the_operator_allow_list() {
        assert!(host_allowed("viz.internal:8080", &allowed()));
        assert!(host_allowed("VIZ.INTERNAL", &allowed()));
        assert!(!host_allowed("viz.internal", &[]));
    }

    #[test]
    fn test_origin_allowed() {
        assert!(origin_allowed("http://127.0.0.1:8080", &allowed()));
        assert!(origin_allowed("http://localhost:8080", &allowed()));
        assert!(origin_allowed("https://viz.internal", &allowed()));
        assert!(!origin_allowed("http://evil.example", &allowed()));
        assert!(!origin_allowed("null", &allowed()));
        assert!(!origin_allowed("", &allowed()));
        assert!(!origin_allowed("http://", &allowed()));
    }

    #[test]
    fn test_strip_port() {
        assert_eq!(strip_port("127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(strip_port("127.0.0.1"), "127.0.0.1");
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("::1"), "::1");
        assert_eq!(strip_port("localhost"), "localhost");
    }
}
