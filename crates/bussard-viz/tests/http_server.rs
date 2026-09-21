//! End-to-end HTTP test: bind a real listener on `127.0.0.1:0`, point the bus at
//! a dead gateway (`127.0.0.1:1`), and drive the server with a plain
//! `TcpStream` speaking HTTP/1.0 — no HTTP client dependency.
//!
//! Asserts that `/api/model` serves the projection and `/api/state` reports the
//! bus as not-connected while the actor keeps retrying in the background (the
//! model-only views work regardless of the bus).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::PathBuf;

use bussard_transport::{ConnectionConfig, TransportKind};
use bussard_viz::VizConfig;

/// Writes a minimal but valid model directory into `dir` and returns it.
fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("bussard.yaml"),
        "connection:\n  transport: tunnel\n  gateway: 127.0.0.1:1\n",
    )?;
    std::fs::write(
        dir.join("groups.yaml"),
        "groups:\n  \"3/2/0\":\n    name: Wind Alarm\n    dpt: \"1.005\"\n",
    )?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    Ok(())
}

/// Sends a raw HTTP/1.0 GET and returns the full response text.
fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf)
}

/// Splits an HTTP response into (status-line + headers, body).
fn split_body(response: &str) -> (&str, &str) {
    match response.split_once("\r\n\r\n") {
        Some((head, body)) => (head, body),
        None => (response, ""),
    }
}

#[tokio::test]
async fn model_only_degradation_over_real_http() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let dir: PathBuf = tmp.path().join("knx");
    write_model(&dir)?;

    // A dead gateway: 127.0.0.1:1 never accepts a tunnel, so the actor stays in
    // Connecting/Reconnecting forever. The read views must still work.
    let connection = ConnectionConfig {
        transport: TransportKind::Tunnel,
        gateway: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)),
        multicast: SocketAddrV4::new(Ipv4Addr::new(224, 0, 23, 12), 3671),
        local_interface: Ipv4Addr::UNSPECIFIED,
    };

    let config = VizConfig {
        dir: dir.clone(),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        connection: Some(connection),
        // The programming-mode watch is off here: this test exercises the
        // read/state endpoints, not the probe.
        watch_prog: false,
        allow_writes: false,
        allowed_hosts: Vec::new(),
    };

    // Build the state and router, bind an ephemeral port, and serve on a task.
    let (state, handle, _watch) = bussard_viz::build_state(&config)?;
    let app = bussard_viz::router(state);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // GET /api/model on a blocking thread (plain TcpStream is sync).
    let model_resp = tokio::task::spawn_blocking(move || http_get(addr, "/api/model")).await??;
    let (head, body) = split_body(&model_resp);
    assert!(
        head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200"),
        "status: {head}"
    );
    let model: serde_json::Value = serde_json::from_str(body)?;
    assert_eq!(model["stats"]["groups"], 1);
    assert_eq!(model["groups"][0]["address"], "3/2/0");

    // GET /api/state: the bus is not connected (dead gateway), and the actor is
    // still retrying — the endpoint reports a non-connected state, never 5xx.
    let state_resp = tokio::task::spawn_blocking(move || http_get(addr, "/api/state")).await??;
    let (head, body) = split_body(&state_resp);
    assert!(head.contains("200"), "state status: {head}");
    let st: serde_json::Value = serde_json::from_str(body)?;
    assert_eq!(st["bus"]["connected"], false);
    // The bus is configured (tunnel), so state is connecting/reconnecting — not
    // the model-only "disconnected".
    let bus_state = st["bus"]["state"].as_str().unwrap_or("");
    assert!(
        matches!(bus_state, "connecting" | "reconnecting"),
        "bus state should be retrying, got {bus_state:?}"
    );
    assert_eq!(st["bus"]["transport"], "tunnel");

    server.abort();
    let _ = handle.expect("bus handle present").close().await;
    Ok(())
}

#[tokio::test]
async fn model_only_mode_with_no_connection() -> Result<(), Box<dyn std::error::Error>> {
    // With connection: None the server serves reads and reports `disconnected`.
    let tmp = tempfile::tempdir()?;
    let dir: PathBuf = tmp.path().join("knx");
    write_model(&dir)?;

    let config = VizConfig {
        dir: dir.clone(),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        connection: None,
        watch_prog: false,
        allow_writes: false,
        allowed_hosts: Vec::new(),
    };
    let (state, handle, watch) = bussard_viz::build_state(&config)?;
    assert!(handle.is_none(), "no bus handle in model-only mode");
    assert!(watch.is_none(), "no watch task in model-only mode");
    let app = bussard_viz::router(state);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let state_resp = tokio::task::spawn_blocking(move || http_get(addr, "/api/state")).await??;
    let (_head, body) = split_body(&state_resp);
    let st: serde_json::Value = serde_json::from_str(body)?;
    assert_eq!(st["bus"]["state"], "disconnected");
    assert_eq!(st["bus"]["connected"], false);

    server.abort();
    Ok(())
}
