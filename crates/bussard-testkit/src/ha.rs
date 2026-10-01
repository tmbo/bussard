//! A mock Home Assistant REST API (issue #280).
//!
//! [`MockHomeAssistant`] serves the handful of endpoints the MCP server's Home
//! Assistant tier calls, on `127.0.0.1:0`, from a plain thread (no runtime):
//!
//! - `GET /api/`: `{"message": "API running."}`
//! - `GET /api/config`: the version, the location name and the loaded
//!   components (`knx` among them unless [`MockHaConfig::knx_loaded`] is off)
//! - `GET /api/states`: the configured entity states
//! - `GET /api/config/config_entries/entry`: the configured config entries, or
//!   404 when [`MockHaConfig::config_entries`] is `None`
//! - `POST /api/services/knx/reload`: `[]`, counted
//!
//! Every request without `Authorization: Bearer <token>` gets 401, like Home
//! Assistant. Each request is recorded ([`MockHomeAssistant::requests`]) with
//! whether it carried the right token, so a test can assert what was called
//! and in which order. The server stops when the value is dropped.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// What the mock Home Assistant answers.
#[derive(Debug, Clone)]
pub struct MockHaConfig {
    /// The bearer token the mock accepts.
    pub token: String,
    /// The version `/api/config` reports.
    pub version: String,
    /// Whether `knx` is among the loaded components.
    pub knx_loaded: bool,
    /// The JSON array `/api/states` returns.
    pub states: String,
    /// The JSON array the config entries endpoint returns; `None` answers 404.
    pub config_entries: Option<String>,
    /// The status `POST /api/services/knx/reload` answers with.
    pub reload_status: u16,
}

impl MockHaConfig {
    /// A Home Assistant with the KNX integration loaded, one KNX config entry
    /// and no entities, accepting `token`.
    pub fn new(token: &str) -> Self {
        MockHaConfig {
            token: token.to_string(),
            version: "2026.9.2".to_string(),
            knx_loaded: true,
            states: "[]".to_string(),
            config_entries: Some(
                r#"[{"entry_id":"01J0KNX","domain":"knx","title":"KNX","state":"loaded","source":"user"},
                   {"entry_id":"01J0SUN","domain":"sun","title":"Sun","state":"loaded","source":"import"}]"#
                    .to_string(),
            ),
            reload_status: 200,
        }
    }

    /// Sets the `/api/states` body from `(entity_id, friendly_name)` pairs.
    pub fn with_entities(mut self, entities: &[(&str, &str)]) -> Self {
        let items: Vec<String> = entities
            .iter()
            .map(|(id, name)| {
                format!(
                    r#"{{"entity_id":"{}","state":"off","attributes":{{"friendly_name":"{}"}}}}"#,
                    escape(id),
                    escape(name)
                )
            })
            .collect();
        self.states = format!("[{}]", items.join(","));
        self
    }
}

/// One request the mock received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The HTTP method, e.g. `GET`.
    pub method: String,
    /// The request path, query included.
    pub path: String,
    /// Whether the request carried the configured bearer token.
    pub authorized: bool,
    /// The request body.
    pub body: String,
}

/// A running mock Home Assistant on a loopback port.
pub struct MockHomeAssistant {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MockHomeAssistant {
    /// Binds `127.0.0.1:0` and serves `config` until dropped.
    ///
    /// # Errors
    ///
    /// The I/O error of binding the listener.
    pub fn start(config: MockHaConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        let _ = serve_one(stream, &config, &requests);
                    }
                }
            })
        };
        Ok(MockHomeAssistant {
            addr,
            requests,
            stop,
            thread: Some(thread),
        })
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The base URL, e.g. `http://127.0.0.1:41234`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .map(|list| list.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// How many authorized `knx.reload` service calls were received.
    pub fn reloads(&self) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == "POST" && r.path == "/api/services/knx/reload" && r.authorized)
            .count()
    }
}

impl Drop for MockHomeAssistant {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept so the thread sees the flag.
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Reads one request from `stream`, records it and answers it.
fn serve_one(
    stream: TcpStream,
    config: &MockHaConfig,
    requests: &Mutex<Vec<RecordedRequest>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    if method.is_empty() {
        return Ok(());
    }
    let mut authorized = false;
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("authorization") {
                authorized = value == format!("Bearer {}", config.token);
            } else if name.eq_ignore_ascii_case("content-length") {
                length = value.parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8_lossy(&body).into_owned();
    if let Ok(mut list) = requests.lock() {
        list.push(RecordedRequest {
            method: method.clone(),
            path: path.clone(),
            authorized,
            body,
        });
    }
    let (status, payload) = if !authorized {
        (401, r#"{"message":"401: Unauthorized"}"#.to_string())
    } else {
        respond(config, &method, &path)
    };
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )?;
    stream.flush()
}

/// The status and body for an authorized request.
fn respond(config: &MockHaConfig, method: &str, path: &str) -> (u16, String) {
    let route = path.split('?').next().unwrap_or(path);
    match (method, route) {
        ("GET", "/api/") => (200, r#"{"message":"API running."}"#.to_string()),
        ("GET", "/api/config") => {
            let mut components = vec!["\"http\"", "\"api\"", "\"sun\""];
            if config.knx_loaded {
                components.extend(["\"knx\"", "\"light.knx\"", "\"switch.knx\""]);
            }
            (
                200,
                format!(
                    r#"{{"version":"{}","location_name":"Mock Home","components":[{}]}}"#,
                    escape(&config.version),
                    components.join(",")
                ),
            )
        }
        ("GET", "/api/states") => (200, config.states.clone()),
        ("GET", "/api/config/config_entries/entry") => match &config.config_entries {
            Some(body) => (200, body.clone()),
            None => (404, r#"{"message":"Not Found"}"#.to_string()),
        },
        ("POST", "/api/services/knx/reload") => (config.reload_status, "[]".to_string()),
        _ => (404, r#"{"message":"Not Found"}"#.to_string()),
    }
}

/// Escapes `"` and `\` for a JSON string literal.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}
