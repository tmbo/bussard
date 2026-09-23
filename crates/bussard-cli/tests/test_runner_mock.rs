//! End-to-end test of `bussard test` against an in-process mock KNX gateway
//! (issue #101).
//!
//! The mock gateway answers a group write on one address with an indication on
//! another, which is exactly the "the light switched and reported back" shape an
//! acceptance test checks. The fixture file exercises every outcome: a passing
//! test, a failing one (the report must name the observed value and the command
//! must exit non-zero), a protected group address (refused, and the gateway must
//! never see the write), and a manual step (skipped without a terminal).
//!
//! Everything binds `127.0.0.1:0`, so no real gateway is ever contacted.

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, MessageCode};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x21;

/// The device the mock answers as.
const RESPONDER: &str = "1.1.30";

fn knxnet_frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (6 + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.push(0x06);
    out.push(0x10);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn connect_response_body(channel: u8, port: u16) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

/// How the simulated installation reacts to a write.
///
/// `1/0/10` is a working light: its status object repeats whatever was written.
/// `1/0/11` is a broken one: its status object always reports off.
fn reaction(ga: GroupAddress, payload: &[u8]) -> Option<(GroupAddress, Vec<u8>)> {
    if ga == "1/0/10".parse().ok()? {
        return Some(("1/0/12".parse().ok()?, payload.to_vec()));
    }
    if ga == "1/0/11".parse().ok()? {
        return Some(("1/0/13".parse().ok()?, vec![0x00]));
    }
    None
}

/// Runs the mock gateway. Records every group address written to, so the test
/// can assert that a refused protected GA never reached the bus.
async fn run_gateway(
    socket: Arc<UdpSocket>,
    port: u16,
    written: Arc<std::sync::Mutex<Vec<String>>>,
    writes: Arc<AtomicUsize>,
) {
    let gw_seq = AtomicU8::new(0);
    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(60), socket.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => break,
            };
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                let resp = knxnet_frame(
                    ServiceType::ConnectResponse,
                    &connect_response_body(CHANNEL, port),
                );
                let _ = socket.send_to(&resp, from).await;
            }
            ServiceType::ConnectionstateRequest => {
                let _ = socket
                    .send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await;
            }
            ServiceType::DisconnectRequest => {
                // Keep serving: the determinism check connects a second time.
                let _ = socket
                    .send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await;
            }
            ServiceType::TunnelingRequest => {
                let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) else {
                    continue;
                };
                let _ = socket
                    .send_to(
                        &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                        from,
                    )
                    .await;
                answer(&socket, from, &tr.cemi, &gw_seq, &written, &writes).await;
            }
            _ => {}
        }
    }
}

/// Records a group write and pushes the installation's reaction, if any.
async fn answer(
    socket: &UdpSocket,
    peer: SocketAddr,
    cemi: &CemiFrame,
    gw_seq: &AtomicU8,
    written: &Arc<std::sync::Mutex<Vec<String>>>,
    writes: &Arc<AtomicUsize>,
) {
    let Destination::Group(ga) = cemi.destination else {
        return;
    };
    let Apdu::GroupValueWrite(data) = &cemi.apdu else {
        return;
    };
    writes.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut log) = written.lock() {
        log.push(ga.to_string());
    }

    let Some((target, payload)) = reaction(ga, &data.bytes()) else {
        return;
    };
    let source: IndividualAddress = RESPONDER.parse().expect("responder address");
    let mut out = CemiFrame::group_write_packed(target, source, &payload);
    out.message_code = MessageCode::LDataInd;
    let header = ConnectionHeader {
        channel_id: CHANNEL,
        seq: gw_seq.fetch_add(1, Ordering::SeqCst),
    };
    let _ = socket
        .send_to(&knxnet::tunneling_request(header, &out), peer)
        .await;
}

/// Writes the fixture model and its acceptance-test file.
fn write_fixture(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("groups.yaml"),
        "groups:\n\
         \x20 \"1/0/10\":\n    name: Kitchen ceiling light\n    dpt: \"1.001\"\n\
         \x20 \"1/0/11\":\n    name: Hall light\n    dpt: \"1.001\"\n\
         \x20 \"1/0/12\":\n    name: Kitchen ceiling light status\n    dpt: \"1.001\"\n\
         \x20 \"1/0/13\":\n    name: Hall light status\n    dpt: \"1.001\"\n\
         \x20 \"3/1/0\":\n    name: Wind alarm\n    dpt: \"1.005\"\n    protected: true\n",
    )?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    std::fs::write(
        dir.join("tests.yaml"),
        "tests:\n\
         \x20 - name: Kitchen light switches and reports\n\
         \x20   write: { ga: \"1/0/10\", value: on }\n\
         \x20   expect: { ga: \"1/0/12\", value: on, within: 5s }\n\
         \x20 - name: Hall light reports what it was told\n\
         \x20   write: { ga: \"1/0/11\", value: on }\n\
         \x20   expect: { ga: \"1/0/13\", value: on, within: 2s }\n\
         \x20 - name: Wind alarm raises the blinds\n\
         \x20   write: { ga: \"3/1/0\", value: alarm }\n\
         \x20   expect: { ga: \"3/2/0\", value: on, within: 1s }\n\
         \x20 - name: Rain sensor reports\n\
         \x20   manual: Pour water on the rain sensor\n\
         \x20   expect: { ga: \"1/0/12\", value: on, within: 1s }\n",
    )?;
    Ok(())
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bussard-testrun-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn test_runner_reports_pass_fail_refusal_and_skip() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let (socket, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind mock gateway");
        let port = sock.local_addr().expect("local addr").port();
        (Arc::new(sock), port)
    });

    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writes = Arc::new(AtomicUsize::new(0));
    let gateway = rt.spawn(run_gateway(socket, port, written.clone(), writes.clone()));

    let tmp = temp_dir("mixed");
    let model_dir = tmp.join("knx");
    write_fixture(&model_dir)?;
    let dir_arg = model_dir.to_str().ok_or("utf-8 dir")?.to_string();
    let gateway_arg = format!("127.0.0.1:{port}");

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "test",
            "--yes",
            "--dir",
            &dir_arg,
            "--gateway",
            &gateway_arg,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // One test fails, so the run exits non-zero.
    assert!(
        !output.status.success(),
        "a failing expectation must exit non-zero.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("PASS Kitchen light switches and reports"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("FAIL Hall light reports what it was told"),
        "stdout:\n{stdout}"
    );
    // The failure names what actually arrived.
    assert!(
        stdout.contains("observed:") && stdout.contains("1/0/13"),
        "a failure must report the observed value.\nstdout:\n{stdout}"
    );
    // The protected GA is refused, not run.
    assert!(
        stdout.contains("REFU Wind alarm raises the blinds"),
        "stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("allow_protected") && stderr.contains("--force"),
        "the refusal must name both opt-ins.\nstderr:\n{stderr}"
    );
    // The manual step is skipped without a terminal.
    assert!(
        stdout.contains("SKIP Rain sensor reports"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("1 passed, 1 failed, 1 skipped, 1 refused"),
        "stdout:\n{stdout}"
    );

    // The protected group address never reached the bus.
    let log = written.lock().map_err(|_| "write log poisoned")?.clone();
    assert!(
        !log.iter().any(|ga| ga == "3/1/0"),
        "a refused test must not write: {log:?}"
    );
    assert!(log.contains(&"1/0/10".to_string()), "{log:?}");

    // The report is deterministic apart from timestamps: the text report has
    // none, so a second run over the same installation renders identically.
    let second = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "test",
            "--yes",
            "--dir",
            &dir_arg,
            "--gateway",
            &gateway_arg,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(
        String::from_utf8_lossy(&second.stdout),
        stdout,
        "two runs of the same installation must render the same report"
    );

    rt.block_on(async { gateway.abort() });
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn test_runner_only_filter_and_json_report() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let (socket, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind mock gateway");
        let port = sock.local_addr().expect("local addr").port();
        (Arc::new(sock), port)
    });

    let written = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writes = Arc::new(AtomicUsize::new(0));
    let gateway = rt.spawn(run_gateway(socket, port, written.clone(), writes.clone()));

    let tmp = temp_dir("only");
    let model_dir = tmp.join("knx");
    write_fixture(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "test",
            "--yes",
            "--json",
            "--only",
            "kitchen light switches and reports",
            "--dir",
            model_dir.to_str().ok_or("utf-8 dir")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "the selected test passes, so the run exits 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("--json must emit valid JSON: {e}\n{stdout}"))?;
    assert_eq!(report["summary"]["total"], 1, "{stdout}");
    assert_eq!(report["summary"]["passed"], 1, "{stdout}");
    assert_eq!(report["summary"]["failed"], 0, "{stdout}");
    assert_eq!(report["summary"]["ok"], true, "{stdout}");
    assert_eq!(
        report["tests"][0]["name"], "Kitchen light switches and reports",
        "{stdout}"
    );
    assert_eq!(report["tests"][0]["status"], "pass", "{stdout}");
    assert!(report["started_at"].is_string(), "{stdout}");

    // Only the selected test's write went out.
    assert_eq!(writes.load(Ordering::SeqCst), 1);

    rt.block_on(async { gateway.abort() });
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}
