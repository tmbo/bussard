//! The streamable HTTP transport (issue #265): the same server, tools and
//! gates as stdio, reachable at a URL for clients that take one.
//!
//! [`serve_on`] mounts rmcp's [`StreamableHttpService`] at [`MCP_PATH`]. Every
//! MCP session gets a clone of one [`crate::server::BussardMcp`], so all sessions share the
//! server's single bus connection, its warm management connection and its
//! limiters, exactly as the one stdio client does.
//!
//! The listener is loopback by default. [`HttpOptions::check`] refuses any
//! other address unless the operator opted in with `--allow-remote-clients`
//! and a bearer token is set; every request must then carry
//! `Authorization: Bearer <token>`. bussard never terminates TLS: a client
//! that needs HTTPS (Claude Desktop's custom connectors) reaches the server
//! through a reverse proxy or a tunnel the operator runs.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

/// The path the MCP endpoint is served at: `http://<listen>/mcp`.
pub const MCP_PATH: &str = "/mcp";

/// The environment variable a bearer token is taken from.
pub const TOKEN_ENV: &str = "BUSSARD_MCP_TOKEN";

/// The default `--listen` address: loopback, a free port picked by the OS.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:0";

/// How the HTTP transport listens and whom it lets in.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// The address to bind. Port 0 picks a free port.
    pub listen: SocketAddr,
    /// The operator passed `--allow-remote-clients`: a non-loopback bind is
    /// permitted (with a bearer token), and the `Host` header check is off
    /// because a reverse proxy forwards its own host name.
    pub allow_remote_clients: bool,
    /// The bearer token every request must present, if any. Required for a
    /// non-loopback bind.
    pub bearer_token: Option<String>,
    /// Extra `Host` header values accepted on a loopback bind, for a reverse
    /// proxy or tunnel that forwards its public host name (`--allow-host`).
    pub allowed_hosts: Vec<String>,
}

impl HttpOptions {
    /// Loopback options for `listen`: no token, no extra hosts.
    pub fn loopback(listen: SocketAddr) -> Self {
        Self {
            listen,
            allow_remote_clients: false,
            bearer_token: None,
            allowed_hosts: Vec::new(),
        }
    }

    /// Refuses a non-loopback bind without `--allow-remote-clients`, and one
    /// with it but without a bearer token. Called before the model loads and
    /// before any bus contact.
    pub fn check(&self) -> anyhow::Result<()> {
        if self.listen.ip().is_loopback() {
            return Ok(());
        }
        if !self.allow_remote_clients {
            anyhow::bail!(
                "refusing to listen on {}: it is not a loopback address, and the MCP \
                 server would be reachable from the network. Bind 127.0.0.1 and put a \
                 reverse proxy or tunnel in front for TLS and authentication, or pass \
                 --allow-remote-clients to accept network clients with a bearer token",
                self.listen
            );
        }
        if self.bearer_token.as_deref().is_none_or(str::is_empty) {
            anyhow::bail!(
                "refusing to listen on {} without a bearer token: set {TOKEN_ENV} or let \
                 the server generate one",
                self.listen
            );
        }
        Ok(())
    }
}

/// The URL a client connects to for a server bound to `addr`.
pub fn url(addr: SocketAddr) -> String {
    format!("http://{addr}{MCP_PATH}")
}

/// A fresh bearer token: 32 random bytes from the OS, hex-encoded.
pub fn generate_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow::anyhow!("no OS randomness for the bearer token: {e}"))?;
    Ok(bussard_model::text::hex(&bytes))
}

/// The axum app: the MCP endpoint at [`MCP_PATH`], behind the bearer check
/// when `options` has a token. Returns the app and a callback that ends every
/// open MCP session (for shutdown).
fn app<S>(server: S, options: &HttpOptions) -> (axum::Router, impl FnOnce() + Send + use<S>)
where
    S: rmcp::ServerHandler + Clone + Send + Sync + 'static,
{
    let mut config = StreamableHttpServerConfig::default();
    if options.allow_remote_clients {
        // A reverse proxy forwards its own host name; the token guards the
        // endpoint instead of the DNS-rebinding check.
        config = config.disable_allowed_hosts();
    } else if !options.allowed_hosts.is_empty() {
        let mut hosts = config.allowed_hosts.clone();
        hosts.extend(options.allowed_hosts.iter().cloned());
        config = config.with_allowed_hosts(hosts);
    }
    let cancel = config.cancellation_token.clone();
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let mut router = axum::Router::new().route_service(MCP_PATH, service);
    if let Some(token) = options.bearer_token.as_deref() {
        router = router.layer(middleware::from_fn_with_state(
            Arc::<str>::from(token),
            require_bearer,
        ));
    }
    (router, move || cancel.cancel())
}

/// Serves MCP over streamable HTTP on `listener` until `shutdown` resolves,
/// then ends every open session and returns.
pub async fn serve_on<S>(
    listener: tokio::net::TcpListener,
    server: S,
    options: &HttpOptions,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()>
where
    S: rmcp::ServerHandler + Clone + Send + Sync + 'static,
{
    let (router, end_sessions) = app(server, options);
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown.await;
            end_sessions();
        })
        .await
        .map_err(|e| anyhow::anyhow!("MCP HTTP server error: {e}"))
}

/// Lets a request through only with `Authorization: Bearer <token>`.
async fn require_bearer(State(token): State<Arc<str>>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if presented.is_some_and(|p| constant_time_eq(p.as_bytes(), token.as_bytes())) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing or wrong bearer token",
        )
            .into_response()
    }
}

/// Compares two byte strings in time independent of where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_check_loopback_needs_nothing() -> TestResult {
        HttpOptions::loopback("127.0.0.1:0".parse()?).check()?;
        HttpOptions::loopback("[::1]:0".parse()?).check()?;
        Ok(())
    }

    #[test]
    fn test_check_refuses_non_loopback_without_opt_in() -> TestResult {
        let mut options = HttpOptions::loopback("0.0.0.0:0".parse()?);
        options.bearer_token = Some("t".to_owned());
        let err = options.check().err().ok_or("must refuse")?;
        assert!(err.to_string().contains("--allow-remote-clients"), "{err}");
        Ok(())
    }

    #[test]
    fn test_check_refuses_non_loopback_without_token() -> TestResult {
        let mut options = HttpOptions::loopback("192.0.2.7:8000".parse()?);
        options.allow_remote_clients = true;
        assert!(options.check().is_err());
        options.bearer_token = Some(String::new());
        assert!(options.check().is_err());
        options.bearer_token = Some("secret".to_owned());
        options.check()?;
        Ok(())
    }

    #[test]
    fn test_generate_token_is_64_hex_and_fresh() -> TestResult {
        let a = generate_token()?;
        let b = generate_token()?;
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn test_url_has_the_path() -> TestResult {
        assert_eq!(url("127.0.0.1:4100".parse()?), "http://127.0.0.1:4100/mcp");
        Ok(())
    }
}
