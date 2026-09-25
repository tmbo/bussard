//! Headless-browser smoke test for the viz frontend (issue #68).
//!
//! This whole file is gated behind the `browser-tests` cargo feature and is
//! **off by default**: a plain `cargo test -p bussard-viz` never compiles or
//! runs it. Enable it with
//! `cargo nextest run -p bussard-viz --features browser-tests`.
//!
//! ## Why a subprocess, not the `headless_chrome` crate
//!
//! The original plan (issue #68) proposed the `headless_chrome` crate to drive
//! Chrome over the DevTools protocol. That crate was **rejected by the license
//! gate**: its build dependency `auto_generate_cdp` ships a `GPL-3.0-or-later`
//! LICENSE, and bussard must never take on a copyleft dependency (see
//! `deny.toml` / `CLAUDE.md`). `cargo deny check` fails on it.
//!
//! So this test drives Chrome directly as a **subprocess** via
//! `std::process::Command`, using `--headless=new --dump-dom`. That adds **no
//! new dependency at all**. The trade-off is reduced coverage: `--dump-dom`
//! gives us the fully-rendered DOM (after JS boot + fetches settle under
//! `--virtual-time-budget`), so we can assert on the self-test title and the
//! rendered cards/tree, but we cannot observe the CDP console-message channel,
//! so the "no console errors of severity error" assertion is not available on
//! this path. We compensate by asserting the DOM rendered the shapes we expect
//! (a boot that threw would leave the containers empty).
//!
//! ## What it checks
//!
//! 1. Boots the viz server in-process on `127.0.0.1:0` against a temp-dir model
//!    (3 devices, a small GA tree), with NO bus (model-only mode).
//! 2. Loads `/assets/test.html` and asserts the store self-test reports
//!    `FAIL 0` in the document title.
//! 3. Asserts the self-test ran its page-shell checks (issue #252): the
//!    inspector's default width, no horizontal overflow of any synthetic-fixture
//!    channel table at the default and minimum widths, and no endpoint in the
//!    reload help.
//! 4. Loads `/` and asserts the expected number of device cards rendered, that
//!    the GA tree has rows, and that the reload tooltip and help text name no
//!    endpoint or method.
//!
//! It **skips gracefully** (prints a note and returns `Ok`) when no Chrome /
//! Chromium binary is found, so it is a no-op on machines without one.

#![cfg(feature = "browser-tests")]

use std::error::Error;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use bussard_viz::VizConfig;

/// The number of devices in the fixture model — and thus the number of rendered
/// device cards `/` must show.
const FIXTURE_DEVICE_COUNT: usize = 3;

/// Hard wall-clock cap for a single Chrome invocation. Headless Chrome prints
/// the dumped DOM and then *keeps running* (the page holds connections open), so
/// [`dump_dom`] returns as soon as it has read a complete document; this bound
/// only guards against a Chrome that never produces one. nextest's own
/// slow-timeout also applies; this is the explicit belt-and-braces bound.
const CHROME_TIMEOUT: Duration = Duration::from_secs(40);

/// Locates a Chrome/Chromium binary: `$CHROME` first, then the standard
/// mac/linux install paths. Returns `None` when none is found (test skips).
fn find_chrome() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHROME") {
        let path = PathBuf::from(&p);
        if path.is_file() {
            return Some(path);
        }
    }
    const CANDIDATES: &[&str] = &[
        // macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        // Linux (GitHub runners ship `google-chrome`)
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ];
    CANDIDATES.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// Writes a minimal but valid model directory into `dir`:
///
/// * `groups.toml` — a small GA tree (two mains, a few subs) so the GA tree
///   renders multiple rows;
/// * `devices/*.toml` — [`FIXTURE_DEVICE_COUNT`] devices so `/` renders that
///   many cards.
///
/// No `bussard.toml` is written: it is optional, and this test runs the server
/// in model-only mode (no bus), so no connection config is needed.
fn write_model(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("groups.toml"),
        concat!(
            "groups = [\n",
            "  { address = \"1/0/1\", name = \"Hallway Light\", dpt = \"1.001\" },\n",
            "  { address = \"1/0/2\", name = \"Kitchen Light\", dpt = \"1.001\" },\n",
            "  { address = \"2/1/0\", name = \"Living Room Blind\", dpt = \"1.008\" },\n",
            "]\n",
        ),
    )?;

    let devices_dir = dir.join("devices");
    std::fs::create_dir_all(&devices_dir)?;
    // A minimal device file is just `address` + `name` (see the bussard-model
    // loader tests). Three files → three cards.
    for (ia, name) in [
        ("1.1.1", "Push Button Hallway"),
        ("1.1.2", "Switch Actuator"),
        ("1.1.3", "Blind Actuator"),
    ] {
        std::fs::write(
            devices_dir.join(format!("{ia}.toml")),
            format!("address = \"{ia}\"\nname = \"{name}\"\n"),
        )?;
    }
    Ok(())
}

/// axum middleware that neutralizes the live traffic stream for the browser
/// test only.
///
/// The frontend opens an `EventSource` to `/api/traffic`, a Server-Sent-Events
/// stream that never completes. Headless Chrome's `--dump-dom` (and
/// `--virtual-time-budget`) waits for the page to reach network-idle, which an
/// open SSE connection prevents — so the dump would race or hang. Returning
/// `204 No Content` on that one path tells `EventSource` not to (re)connect
/// (per the SSE spec) and lets the page settle deterministically. Every other
/// route — including `/api/model`, which drives the card/tree rendering under
/// test — is untouched, and this override lives only in the test harness, never
/// in the production [`bussard_viz::router`].
async fn neutralize_sse(req: Request, next: Next) -> Response {
    if req.uri().path() == "/api/traffic" {
        return StatusCode::NO_CONTENT.into_response();
    }
    next.run(req).await
}

/// Runs Chrome headless against `url` and returns the dumped DOM.
///
/// Chrome prints the serialized DOM to stdout once the page has rendered, then
/// keeps running (open connections). So instead of waiting for the process to
/// exit, this reads stdout until it contains a complete document
/// (`</html>`), then kills Chrome and returns. [`CHROME_TIMEOUT`] bounds the
/// wait so a Chrome that never renders cannot wedge the test.
fn dump_dom(chrome: &Path, url: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    // A throwaway user-data-dir keeps runs hermetic (no shared profile lock).
    let profile = tempfile::tempdir()?;
    let mut child = Command::new(chrome)
        .arg("--headless=new")
        .arg("--disable-gpu")
        .arg("--no-sandbox")
        .arg("--no-first-run")
        .arg("--disable-extensions")
        .arg("--disable-dev-shm-usage")
        .arg(format!("--user-data-dir={}", profile.path().display()))
        // Let the page's async boot (module imports + fetch /api/model) settle
        // before the DOM is serialized.
        .arg("--virtual-time-budget=5000")
        .arg("--dump-dom")
        .arg(url)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // Read stdout on a helper thread, chunk by chunk, so the timeout applies
    // even if Chrome never produces output. The thread forwards every chunk
    // and ends at EOF (Chrome exited, or we killed it).
    let mut stdout = child
        .stdout
        .take()
        .ok_or("chrome child had no stdout pipe")?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(chunk[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Return as soon as the complete document is in: some pages (the index
    // page with its EventSource, and on some Chrome builds the self-test page)
    // keep Chrome running after `--dump-dom` has flushed, so waiting for exit
    // or for a fixed grace window races a slow runner (issue #252: CI killed
    // Chrome at 8 s before the self-test page was dumped). A Chrome that exits
    // ends the stream; [`CHROME_TIMEOUT`] bounds one that never dumps.
    let start = Instant::now();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if String::from_utf8_lossy(&buf).contains("</html>") {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if start.elapsed() > CHROME_TIMEOUT {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    // Not joined: a Chrome helper process can hold the pipe open a little
    // longer; the thread ends on its own at EOF.
    drop(reader);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Counts non-overlapping occurrences of `needle` in `haystack`.
fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// A multi-thread runtime so the axum server task keeps making progress on a
// worker thread while the test thread is parked awaiting the blocking Chrome
// invocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_smoke_dom_renders() -> Result<(), Box<dyn Error + Send + Sync>> {
    let Some(chrome) = find_chrome() else {
        eprintln!(
            "browser_smoke: no Chrome/Chromium binary found \
             (set $CHROME or install to a standard path) — skipping"
        );
        return Ok(());
    };
    eprintln!("browser_smoke: using Chrome at {}", chrome.display());

    // --- boot the viz server in-process, model-only (no bus) ----------------
    let tmp = tempfile::tempdir()?;
    let dir: PathBuf = tmp.path().join("knx");
    write_model(&dir)?;

    let config = VizConfig {
        dir: dir.clone(),
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        connection: None, // model-only mode: no bus, reads still work
        watch_prog: false,
        allow_writes: false,
        allow_remote_gateway: false,
        allowed_hosts: Vec::new(),
        group_keys: None,
    };
    let (state, handle, _watch) = bussard_viz::build_state(&config)?;
    assert!(handle.is_none(), "model-only mode must not open a bus");
    let app = bussard_viz::router(state).layer(middleware::from_fn(neutralize_sse));
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");

    // --- 1) the store self-test page reports FAIL 0 -------------------------
    // The page writes `PASS n / FAIL n` into its title, so we assert the DOM
    // reports zero failures.
    let test_url = format!("{base}/assets/test.html");
    let chrome_1 = chrome.clone();
    let test_dom = tokio::task::spawn_blocking(move || dump_dom(&chrome_1, &test_url)).await??;
    let title = title_snippet(&test_dom);
    let failures: Vec<&str> = test_dom
        .split("<li class=\"bad\">")
        .skip(1)
        .filter_map(|rest| rest.split('<').next())
        .collect();
    assert!(
        title.contains("FAIL 0"),
        "self-test title should report FAIL 0; got: {title} (RUNNING means the page \
         was dumped before it finished, ERROR a script error); failures: {failures:?}; \
         {} bytes of DOM",
        test_dom.len()
    );
    // The page-shell checks (issue #252) need the server; over HTTP they must
    // have run, not been skipped. They lay index.html out 1600px wide and render
    // every synthetic-fixture device into the inspector.
    for line in [
        "PASS inspector default width is 780px",
        "PASS inspector: no fixture channel table overflows at the default width",
        "PASS inspector: tables wrap instead of overflowing at the minimum width",
        "PASS reload help text has no endpoint or method",
        "PASS inspector: channel parameters render (14 rows)",
        "PASS inspector: non-default values are marked (9)",
    ] {
        assert!(
            test_dom.contains(line),
            "self-test should report `{line}`\nDOM:\n{test_dom}"
        );
    }
    assert!(
        // The rendered `<li>`, not the script source that also holds the text.
        !test_dom.contains(">SKIP page shell checks"),
        "page-shell checks must run when served over HTTP"
    );

    // --- 2) the main page renders cards and a GA tree -----------------------
    let index_url = format!("{base}/");
    let chrome_2 = chrome.clone();
    let index_dom = tokio::task::spawn_blocking(move || dump_dom(&chrome_2, &index_url)).await??;

    // Device cards: each *rendered* card carries a non-empty
    // `data-device="<addr>"` (the inert `<template>` copy has `data-device=""`).
    // Count the fixture addresses to get exactly the rendered cards.
    let rendered_cards = count(&index_dom, "data-device=\"1.");
    assert_eq!(
        rendered_cards, FIXTURE_DEVICE_COUNT,
        "expected {FIXTURE_DEVICE_COUNT} rendered device cards, found {rendered_cards}\nDOM:\n{index_dom}"
    );

    // GA tree: rows carry the `ga-row` class. Three of these come from the inert
    // `<template>` definitions (main/middle/sub); a rendered tree adds more.
    // Asserting strictly more than the three template rows proves the tree
    // actually rendered rows for our fixture groups.
    let ga_rows = count(&index_dom, "class=\"ga-row");
    assert!(
        ga_rows > 3,
        "GA tree should have rendered rows beyond the 3 templates, found {ga_rows}\nDOM:\n{index_dom}"
    );

    // Reload help (issue #252): the tooltip and the help panel describe what a
    // reload does for the user and never name the HTTP endpoint or method.
    let reload_help = [
        attr_of_id(&index_dom, "reload-btn", "title"),
        element_text_by_id(&index_dom, "help-reload"),
    ];
    for text in reload_help {
        let text = text.ok_or("reload tooltip or help text missing from the page")?;
        assert!(
            !text.contains("/api") && !text.contains("POST"),
            "reload help must not name the endpoint: {text}"
        );
        assert!(
            text.contains("import") && text.contains("apply"),
            "reload help should say when to use it: {text}"
        );
    }

    // A boot that threw before rendering would leave both empty; asserting both
    // rendered is our (reduced) stand-in for the CDP "no console errors" check
    // that the subprocess path cannot observe.

    server.abort();
    Ok(())
}

/// Extracts the text inside `<title>…</title>` for a friendlier assertion
/// message, or a placeholder when absent.
fn title_snippet(dom: &str) -> String {
    match (dom.find("<title>"), dom.find("</title>")) {
        (Some(a), Some(b)) if b > a => dom[a + "<title>".len()..b].to_string(),
        _ => "<no <title> found>".to_string(),
    }
}

/// The value of attribute `attr` on the element with `id="<id>"` in a dumped
/// DOM, or `None` when either is absent. Chrome serializes attributes with
/// double quotes, so a plain scan is enough for this test.
fn attr_of_id(dom: &str, id: &str, attr: &str) -> Option<String> {
    let at = dom.find(&format!("id=\"{id}\""))?;
    let start = dom[..at].rfind('<')?;
    let end = at + dom[at..].find('>')?;
    let tag = &dom[start..end];
    let key = format!(" {attr}=\"");
    let v = tag.find(&key)? + key.len();
    let len = tag[v..].find('"')?;
    Some(tag[v..v + len].to_string())
}

/// The raw inner HTML of the element with `id="<id>"`, up to its first closing
/// tag of the same name. Good enough for the flat help paragraphs checked here.
fn element_text_by_id(dom: &str, id: &str) -> Option<String> {
    let at = dom.find(&format!("id=\"{id}\""))?;
    let start = dom[..at].rfind('<')?;
    let name_end = start + 1 + dom[start + 1..].find(|c: char| c.is_whitespace())?;
    let name = &dom[start + 1..name_end];
    let open_end = at + dom[at..].find('>')? + 1;
    let close = open_end + dom[open_end..].find(&format!("</{name}>"))?;
    Some(dom[open_end..close].to_string())
}
