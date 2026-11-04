//! The streamable HTTP transport (issue #265): the same tools behind the same
//! gates as stdio, a loopback-only default, and a bearer token for anything
//! else.
//!
//! Every server here binds `127.0.0.1:0`; no test contacts a gateway (the
//! write-gate test is refused before any bus contact, against a TEST-NET
//! address). The client is a plain HTTP client speaking JSON-RPC, so the test
//! sees exactly what a URL-taking MCP client sees.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bussard_mcp::http::{HttpOptions, MCP_PATH};
use bussard_mcp::server::BussardMcp;
use bussard_mcp::{McpConfig, tools_program};
use bussard_model::Model;
use bussard_testkit::TestResult;
use bussard_transport::ConnectionConfig;
use serde_json::{Value, json};

/// A config for `dir` against a loopback port nothing listens on.
fn config(dir: &Path, passive: bool, allow_writes: bool) -> McpConfig {
    McpConfig {
        dir: dir.to_path_buf(),
        connection: ConnectionConfig::tunnel(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
        passive,
        allow_writes,
        no_model_edits: true,
        capture_db: None,
        allow_programming: false,
        allow_remote_gateway: false,
        plan_ttl: tools_program::DEFAULT_PLAN_TTL,
        keyring: None,
        allow_home_assistant: false,
        viz_listen: None,
    }
}

/// A one-group model written to `dir`.
fn write_model(dir: &Path) -> TestResult {
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/1\", name = \"Light\", dpt = \"1.001\" },\n]\n",
    )?;
    Ok(())
}

/// A server over the model in `dir`, no bus wired.
fn server(dir: &Path, passive: bool, allow_writes: bool) -> TestResult<BussardMcp> {
    let config = config(dir, passive, allow_writes);
    let model = Model::load(dir)?;
    let state = bussard_mcp::build_state_from_model(model, &config)?;
    Ok(BussardMcp::new(state))
}

/// A running HTTP server: its URL and the sender that stops it.
struct Running {
    url: String,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Running {
    async fn stop(self) -> TestResult {
        let _ = self.stop.send(());
        self.task.await??;
        Ok(())
    }
}

/// Serves `server` on a fresh loopback port with `token`.
async fn start(server: BussardMcp, token: Option<&str>) -> TestResult<Running> {
    let mut options = HttpOptions::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    options.bearer_token = token.map(str::to_owned);
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    let url = bussard_mcp::http::url(listener.local_addr()?);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        bussard_mcp::http::serve_on(listener, server, &options, async {
            let _ = stopped.await;
        })
        .await
    });
    Ok(Running { url, stop, task })
}

/// One HTTP exchange's outcome: the status, the session id header and the
/// JSON-RPC message in the body (from JSON or the SSE `data:` lines).
struct Reply {
    status: u16,
    session: Option<String>,
    message: Option<Value>,
}

/// POSTs one JSON-RPC message, blocking (run it off the runtime).
fn post_blocking(
    url: &str,
    session: Option<&str>,
    token: Option<&str>,
    body: &Value,
) -> anyhow::Result<Reply> {
    let mut request = ureq::post(url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream");
    if let Some(session) = session {
        request = request.set("Mcp-Session-Id", session);
    }
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = match request.send_string(&body.to_string()) {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(e) => return Err(e.into()),
    };
    let status = response.status();
    let session = response.header("mcp-session-id").map(str::to_owned);
    let text = response.into_string()?;
    let message = text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .chain(std::iter::once(text.as_str()))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find(|value| value.get("jsonrpc").is_some());
    Ok(Reply {
        status,
        session,
        message,
    })
}

async fn post(
    url: &str,
    session: Option<&str>,
    token: Option<&str>,
    body: Value,
) -> anyhow::Result<Reply> {
    let url = url.to_owned();
    let session = session.map(str::to_owned);
    let token = token.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        post_blocking(&url, session.as_deref(), token.as_deref(), &body)
    })
    .await?
}

/// `initialize` plus `notifications/initialized`; returns the session id.
async fn handshake(url: &str, token: Option<&str>) -> TestResult<String> {
    let reply = post(
        url,
        None,
        token,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "bussard-test", "version": "0"}
        }}),
    )
    .await?;
    assert_eq!(reply.status, 200, "initialize: {:?}", reply.message);
    let message = reply.message.ok_or("initialize: no response")?;
    assert!(message["result"]["serverInfo"].is_object(), "{message}");
    let session = reply.session.ok_or("initialize: no Mcp-Session-Id")?;
    let ack = post(
        url,
        Some(&session),
        token,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await?;
    assert_eq!(ack.status, 202);
    Ok(session)
}

/// Every tool name over HTTP, following `nextCursor`.
async fn tool_names(url: &str, session: &str) -> TestResult<Vec<String>> {
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;
    for id in 2.. {
        let params = match &cursor {
            Some(cursor) => json!({"cursor": cursor}),
            None => json!({}),
        };
        let reply = post(
            url,
            Some(session),
            None,
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params}),
        )
        .await?;
        let message = reply.message.ok_or("tools/list: no response")?;
        let result = &message["result"];
        for tool in result["tools"].as_array().ok_or("no tools array")? {
            names.push(tool["name"].as_str().ok_or("tool without name")?.to_owned());
        }
        match result["nextCursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    names.sort();
    Ok(names)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_serve_on_lists_the_same_tools_as_stdio_in_each_tier() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    for (passive, allow_writes) in [(true, false), (false, false), (false, true)] {
        let running = start(server(dir.path(), passive, allow_writes)?, None).await?;
        assert!(running.url.ends_with(MCP_PATH));
        let session = handshake(&running.url, None).await?;
        let names = tool_names(&running.url, &session).await?;
        let mut expected: Vec<String> = bussard_mcp::tool_names(passive, allow_writes, true)
            .into_iter()
            .map(str::to_owned)
            .collect();
        expected.sort();
        assert_eq!(
            names, expected,
            "passive={passive} allow_writes={allow_writes}"
        );
        assert_eq!(
            names.iter().any(|n| n == "knx_write_group"),
            allow_writes,
            "knx_write_group only with --allow-writes"
        );
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_serve_on_refuses_write_group_without_allow_writes() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let running = start(server(dir.path(), false, false)?, None).await?;
    let session = handshake(&running.url, None).await?;
    let reply = post(
        &running.url,
        Some(&session),
        None,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
            "name": "knx_write_group",
            "arguments": {"ga": "1/0/1", "value": "on"}
        }}),
    )
    .await?;
    let message = reply.message.ok_or("tools/call: no response")?;
    assert!(
        message.get("error").is_some(),
        "knx_write_group must not exist without --allow-writes: {message}"
    );
    running.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_serve_on_requires_the_bearer_token() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let running = start(server(dir.path(), true, false)?, Some("s3cret")).await?;
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "bussard-test", "version": "0"}
    }});
    let missing = post(&running.url, None, None, init.clone()).await?;
    assert_eq!(missing.status, 401);
    let wrong = post(&running.url, None, Some("s3cres"), init).await?;
    assert_eq!(wrong.status, 401);
    handshake(&running.url, Some("s3cret")).await?;
    running.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_run_http_with_ready_refuses_a_non_loopback_bind() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let ready = Arc::new(AtomicBool::new(false));
    let flag = ready.clone();
    let options = HttpOptions::loopback(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    let err = bussard_mcp::run_http_with_ready(&config(dir.path(), true, false), &options, |_| {
        flag.store(true, Ordering::SeqCst)
    })
    .await
    .err()
    .ok_or("a 0.0.0.0 bind without --allow-remote-clients must be refused")?;
    assert!(err.to_string().contains("not a loopback address"), "{err}");
    assert!(!ready.load(Ordering::SeqCst), "the server never came up");

    // Opting in without a token is refused too.
    let mut options = options;
    options.allow_remote_clients = true;
    let err = bussard_mcp::run_http_with_ready(&config(dir.path(), true, false), &options, |_| {
        flag_never()
    })
    .await
    .err()
    .ok_or("a 0.0.0.0 bind without a token must be refused")?;
    assert!(err.to_string().contains("bearer token"), "{err}");
    Ok(())
}

/// An `on_ready` that must not run.
fn flag_never() {
    panic!("the server must not come up");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_run_http_with_ready_applies_the_real_gateway_write_gate() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let mut config = config(dir.path(), false, true);
    // TEST-NET-1: a non-loopback gateway, refused before any bus contact.
    config.connection =
        ConnectionConfig::tunnel(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3671));
    let options = HttpOptions::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let err = bussard_mcp::run_http_with_ready(&config, &options, |_| flag_never())
        .await
        .err()
        .ok_or("--allow-writes against a real gateway without opt-in must be refused")?;
    assert!(
        err.to_string()
            .contains("refusing to write to non-loopback gateway"),
        "{err}"
    );
    Ok(())
}
