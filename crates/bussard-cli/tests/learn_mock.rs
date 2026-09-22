//! End-to-end test of `bussard learn` against an in-process mock KNX gateway
//! (issue #95).
//!
//! The mock gateway pushes a repeating set of group telegrams from a device the
//! fixture model knows, and counts every TUNNELING_REQUEST the client sends. A
//! scripted `--yes` session names and types three group addresses; afterwards
//! the model must pass `bussard validate` with no `W011` (no DPT) warning for
//! any of them, and the gateway must have received **zero** tunnelling requests:
//! learn mode never transmits.
//!
//! Everything binds `127.0.0.1:0`, so no real gateway is ever contacted.

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{CemiFrame, MessageCode};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x21;

/// The device the fixture model knows; every pushed telegram comes from it.
const SENDER: &str = "1.1.30";

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

/// The telegrams the mock bus carries, pushed in a loop.
fn telegrams() -> Vec<(GroupAddress, Vec<u8>)> {
    vec![
        // A 1-bit switch on a GA the model already links to com object 3.
        ("1/0/1".parse().expect("ga"), vec![0x01]),
        // A byte-wide value that reads as a percentage.
        ("1/0/2".parse().expect("ga"), vec![0x32]),
        // 21.5 °C as a 2-byte float.
        ("1/0/3".parse().expect("ga"), vec![0x0c, 0x33]),
    ]
}

/// Runs the mock gateway: answers the KNXnet/IP handshake, pushes bus
/// indications on a timer, and counts the tunnelling requests it receives.
async fn run_gateway(socket: Arc<UdpSocket>, port: u16, requests: Arc<AtomicUsize>) {
    let gw_seq = Arc::new(AtomicU8::new(0));
    let mut pusher: Option<tokio::task::JoinHandle<()>> = None;

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
                if pusher.is_none() {
                    pusher = Some(tokio::spawn(push_telegrams(
                        socket.clone(),
                        from,
                        gw_seq.clone(),
                    )));
                }
            }
            ServiceType::ConnectionstateRequest => {
                let _ = socket
                    .send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await;
            }
            ServiceType::DisconnectRequest => {
                let _ = socket
                    .send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await;
                break;
            }
            ServiceType::TunnelingRequest => {
                // The whole point of the test: learn mode must never get here.
                requests.fetch_add(1, Ordering::SeqCst);
                if let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) {
                    let _ = socket
                        .send_to(
                            &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                            from,
                        )
                        .await;
                }
            }
            _ => {}
        }
    }
    if let Some(pusher) = pusher {
        pusher.abort();
    }
}

/// Pushes the fixture telegrams to the connected client, over and over, so the
/// session sees each group address whenever it starts waiting for it.
async fn push_telegrams(socket: Arc<UdpSocket>, peer: SocketAddr, gw_seq: Arc<AtomicU8>) {
    let source: IndividualAddress = SENDER.parse().expect("sender address");
    let telegrams = telegrams();
    loop {
        for (ga, payload) in &telegrams {
            let mut cemi = CemiFrame::group_write_packed(*ga, source, payload);
            // A bus indication, not our own request echoing back.
            cemi.message_code = MessageCode::LDataInd;
            let header = ConnectionHeader {
                channel_id: CHANNEL,
                seq: gw_seq.fetch_add(1, Ordering::SeqCst),
            };
            let _ = socket
                .send_to(&knxnet::tunneling_request(header, &cemi), peer)
                .await;
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    }
}

/// Writes the fixture model: one device the sender maps to, with a channel, two
/// transmit-capable com objects, and a link for the first group address.
fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(dir.join("groups.yaml"), "groups: {}\n")?;
    std::fs::write(
        dir.join("links.yaml"),
        "links:\n  1.1.30:\n    - object: 3\n      name: Kanal A - Schalten\n      send: 1/0/1\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.30-schaltaktor.yaml"),
        "address: 1.1.30\n\
         name: Schaltaktor\n\
         location:\n  \
           floor: EG\n  \
           room: Kitchen\n\
         channels:\n  \
           A:\n    name: Ceiling light\n\
         com_objects:\n  \
           3:\n    dpt: \"1.001\"\n    flags: CT\n    channel: A\n  \
           4:\n    flags: CT\n    channel: A\n",
    )?;
    Ok(())
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bussard-learn-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn learn_names_and_types_group_addresses_without_transmitting()
-> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    let (socket, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind mock gateway");
        let port = sock.local_addr().expect("local addr").port();
        (Arc::new(sock), port)
    });

    let requests = Arc::new(AtomicUsize::new(0));
    let gateway = rt.spawn(run_gateway(socket, port, requests.clone()));

    let tmp = temp_dir("session");
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "learn",
            "--ga",
            "1/0/1",
            "--ga",
            "1/0/2",
            "--ga",
            "1/0/3",
            "--yes",
            "--timeout",
            "20",
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
        "learn should exit 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Learn mode never transmits: not one tunnelling request reached the bus.
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "learn transmitted on the bus.\nstderr:\n{stderr}"
    );

    // Every target was named and typed in groups.yaml.
    let groups = std::fs::read_to_string(model_dir.join("groups.yaml"))?;
    for ga in ["1/0/1", "1/0/2", "1/0/3"] {
        assert!(
            groups.contains(ga),
            "{ga} missing from groups.yaml:\n{groups}"
        );
    }
    assert!(
        groups.contains("1.001") && groups.contains("5.001") && groups.contains("9.001"),
        "expected the inferred DPTs in groups.yaml:\n{groups}"
    );
    // The name came from the device's room, channel and com-object function.
    assert!(
        groups.to_lowercase().contains("kitchen"),
        "expected a proposed name built from the device location:\n{groups}"
    );

    // The unlinked GA whose sender had exactly one free transmit-capable com
    // object got a links.yaml entry.
    let links = std::fs::read_to_string(model_dir.join("links.yaml"))?;
    assert!(
        links.contains("1/0/2"),
        "expected a learned link for 1/0/2:\n{links}"
    );

    // The acceptance criterion: no W011 (no DPT) for any learned GA.
    let validate = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "validate",
            "--dir",
            model_dir.to_str().ok_or("utf-8 dir")?,
            "--format",
            "json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let diagnostics: serde_json::Value = serde_json::from_slice(&validate.stdout).map_err(|e| {
        format!(
            "validate --format json must emit JSON: {e}\n{}",
            String::from_utf8_lossy(&validate.stdout)
        )
    })?;
    let items = diagnostics
        .as_array()
        .cloned()
        .or_else(|| diagnostics["diagnostics"].as_array().cloned())
        .ok_or("expected a diagnostics array")?;
    for item in &items {
        if item["code"] == "W011" {
            let location = item["location"].as_str().unwrap_or_default();
            for ga in ["1/0/1", "1/0/2", "1/0/3"] {
                assert!(
                    !location.contains(ga),
                    "W011 still reported for the learned GA {ga}: {item}"
                );
            }
        }
    }

    rt.block_on(async { gateway.abort() });
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}
