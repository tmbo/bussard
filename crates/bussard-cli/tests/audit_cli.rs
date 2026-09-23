//! End-to-end tests of `bussard audit` (issue #93) and its full-interface exit
//! code (issue #105).
//!
//! The static tests run on a copy of the small-installation example model. The
//! live test runs against an in-process mock KNXnet/IP gateway on 127.0.0.1
//! that advertises two tunnel slots, pushes a few group telegrams during the
//! traffic window, answers management probes for one device, and records every
//! frame the client sends: the test proves `--live` never transmits a group
//! telegram.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bussard_mgmt::apci;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use serde_json::Value;
use tokio::net::UdpSocket;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHANNEL: u8 = 0x21;

/// Copies the small-installation example model into a fresh temp directory.
fn fixture(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let src =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knx-sim/examples/small-installation/knx");
    let dst = std::env::temp_dir().join(format!("bussard-audit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    copy_dir(&src, &dst)?;
    Ok(dst)
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

fn bussard(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .env("BUSSARD_SCAN_DISCOVERY_MS", "40")
        .output()
}

#[test]
fn test_audit_static_text_has_every_section() -> TestResult {
    let dir = fixture("text")?;
    let out = bussard(&["audit", "--dir", dir.to_str().ok_or("path")?])?;
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for section in [
        "== Model ==",
        "project: small-installation",
        "4 device(s)",
        "line 1.0: 4 device(s)",
        "== Model gaps ==",
        "== Findings (one-sided links) ==",
        "== Devices per mask ==",
        "07B0 System B (4 device(s)): bussard can: plan/apply, flash, reconstruct, describe",
        "== KNX Secure ==",
        "protected GAs",
    ] {
        assert!(stdout.contains(section), "missing {section:?}:\n{stdout}");
    }
    assert!(!stdout.contains("== Gateway =="), "{stdout}");
    Ok(())
}

#[test]
fn test_audit_static_json_matches_sections() -> TestResult {
    let dir = fixture("json")?;
    let out = bussard(&["audit", "--json", "--dir", dir.to_str().ok_or("path")?])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(report["format_version"], 1);
    assert_eq!(report["model"]["devices"], 4);
    assert_eq!(report["model"]["project"], "small-installation");
    assert!(report["model"]["findings"].is_array());
    assert!(report["model"]["info"]["unused_group_addresses"].is_number());
    assert_eq!(report["masks"][0]["mask"], "07B0");
    assert_eq!(report["masks"][0]["plan_apply"], true);
    assert_eq!(
        report["masks"][0]["devices"].as_array().map(Vec::len),
        Some(4)
    );
    assert_eq!(report["secure"]["keyring_checked"], false);
    assert!(report["live"].is_null());
    Ok(())
}

// --- live mock gateway ---------------------------------------------------------

fn frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    knxnet::frame(service, body)
}

fn description_body() -> Vec<u8> {
    let mut body = vec![0u8; 54];
    body[0] = 54;
    body[1] = 0x01;
    body[2] = 0x02;
    body[4..6].copy_from_slice(&0x1000u16.to_be_bytes());
    body[24..33].copy_from_slice(b"Mock Gate");
    body.extend_from_slice(&[12, 0x07, 0x00, 0xF8]);
    body.extend_from_slice(&[0x10, 0xF1, 0x00, 0x06]); // in use
    body.extend_from_slice(&[0x10, 0xF2, 0x00, 0x07]); // free
    body
}

fn connect_response_body(port: u16) -> Vec<u8> {
    let mut body = vec![CHANNEL, 0x00, 0x08, 0x01, 127, 0, 0, 1];
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

struct Mock {
    gw: UdpSocket,
    peer: Option<SocketAddr>,
    gw_seq: u8,
    dev_seq: HashMap<u16, u8>,
    /// Every cEMI frame the client sent, for the no-group-write assertion.
    sent: Arc<Mutex<Vec<CemiFrame>>>,
}

impl Mock {
    async fn push(&mut self, cemi: &CemiFrame) {
        let Some(peer) = self.peer else { return };
        let hdr = ConnectionHeader {
            channel_id: CHANNEL,
            seq: self.gw_seq,
        };
        let _ = self
            .gw
            .send_to(&knxnet::tunneling_request(hdr, cemi), peer)
            .await;
        self.gw_seq = self.gw_seq.wrapping_add(1);
    }

    /// Answers management traffic for the single present device 1.0.1.
    async fn handle(&mut self, cemi: &CemiFrame) {
        let Destination::Individual(dest) = cemi.destination else {
            return;
        };
        let present: IndividualAddress = match "1.0.1".parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        if dest != present {
            return;
        }
        let tool = cemi.source;
        match tpci::classify(cemi.tpci_octet()) {
            TpciKind::Connect => {
                self.dev_seq.insert(dest.raw(), 0);
            }
            TpciKind::Disconnect => {
                self.dev_seq.remove(&dest.raw());
            }
            TpciKind::NumberedData(client_seq) => {
                let ack = CemiFrame::t_control(tool, dest, tpci::t_ack(client_seq));
                self.push(&ack).await;
                let (Tpci::Other(_), Apdu::Other { apci: code, .. }) = (&cemi.tpci, &cemi.apdu)
                else {
                    return;
                };
                let answer = match *code {
                    apci::A_AUTHORIZE_REQUEST => Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00])),
                    apci::A_DEVICE_DESCRIPTOR_READ => {
                        Some((apci::A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]))
                    }
                    _ => None,
                };
                if let Some((rapci, rdata)) = answer {
                    let seq = *self.dev_seq.get(&dest.raw()).unwrap_or(&0);
                    let resp =
                        CemiFrame::t_data_connected(tool, dest, tpci::ndt(seq), rapci, &rdata);
                    self.push(&resp).await;
                    self.dev_seq.insert(dest.raw(), (seq + 1) & 0x0f);
                }
            }
            _ => {}
        }
    }
}

/// Runs the mock until idle. `refuse` answers every CONNECT with 0x24.
async fn run_mock(gw: UdpSocket, sent: Arc<Mutex<Vec<CemiFrame>>>, refuse: bool) {
    let port = gw.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut mock = Mock {
        gw,
        peer: None,
        gw_seq: 0,
        dev_seq: HashMap::new(),
        sent,
    };
    let mut connected_at: Option<Instant> = None;
    let mut pushed = false;
    let idle_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if Instant::now() > idle_deadline {
            return;
        }
        // Once the long-lived bus session has been up briefly, push traffic:
        // two identical writes 50 ms apart (a repetition) and one to a GA the
        // model has no listener for, from a source the model does not know.
        if !pushed && connected_at.is_some_and(|t| t.elapsed() > Duration::from_millis(400)) {
            pushed = true;
            let src: IndividualAddress = "1.0.1"
                .parse()
                .unwrap_or(IndividualAddress::from_raw(0x1001));
            let stranger = IndividualAddress::from_raw(0x10C8); // 1.0.200
            let ga1: GroupAddress = "1/0/2".parse().unwrap_or(GroupAddress::from_raw(0x0802));
            let ga_orphan = GroupAddress::from_raw(0x3F00); // 7/7/0
            let mut w = CemiFrame::group_write_packed(ga1, src, &[1]);
            w.message_code = bussard_transport::cemi::MessageCode::LDataInd;
            mock.push(&w).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            mock.push(&w).await;
            let mut o = CemiFrame::group_write_packed(ga_orphan, stranger, &[0]);
            o.message_code = bussard_transport::cemi::MessageCode::LDataInd;
            mock.push(&o).await;
        }
        let mut buf = [0u8; 1024];
        let (n, from) = match tokio::time::timeout(
            Duration::from_millis(50),
            mock.gw.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => return,
            Err(_) => continue,
        };
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
        };
        match parsed.service {
            ServiceType::DescriptionRequest => {
                let _ = mock
                    .gw
                    .send_to(
                        &frame(ServiceType::DescriptionResponse, &description_body()),
                        from,
                    )
                    .await;
            }
            ServiceType::ConnectRequest => {
                if refuse {
                    let _ = mock
                        .gw
                        .send_to(&frame(ServiceType::ConnectResponse, &[0x00, 0x24]), from)
                        .await;
                    continue;
                }
                mock.peer = Some(from);
                mock.gw_seq = 0;
                connected_at = Some(Instant::now());
                let _ = mock
                    .gw
                    .send_to(
                        &frame(ServiceType::ConnectResponse, &connect_response_body(port)),
                        from,
                    )
                    .await;
            }
            ServiceType::ConnectionstateRequest => {
                let _ = mock
                    .gw
                    .send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await;
            }
            ServiceType::DisconnectRequest => {
                let _ = mock
                    .gw
                    .send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await;
                connected_at = None;
            }
            ServiceType::TunnelingRequest => {
                let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) else {
                    continue;
                };
                let _ = mock
                    .gw
                    .send_to(
                        &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                        from,
                    )
                    .await;
                if let Ok(mut sent) = mock.sent.lock() {
                    sent.push(tr.cemi.clone());
                }
                mock.handle(&tr.cemi).await;
            }
            _ => {}
        }
    }
}

#[test]
fn test_audit_live_reports_gateway_traffic_scan_and_never_writes_a_group() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(UdpSocket::bind("127.0.0.1:0"))?;
    let port = gw.local_addr()?.port();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mock = rt.spawn(run_mock(gw, sent.clone(), false));

    let dir = fixture("live")?;
    let gateway = format!("127.0.0.1:{port}");
    let out = bussard(&[
        "audit",
        "--live",
        "--json",
        "--window",
        "2",
        "--gateway",
        &gateway,
        "--dir",
        dir.to_str().ok_or("path")?,
    ])?;
    mock.abort();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout)?;
    let live = &report["live"];

    assert_eq!(live["gateway"]["name"], "Mock Gate");
    assert_eq!(live["gateway"]["tunnels"], 2);
    assert_eq!(live["gateway"]["tunnels_in_use"], 1);

    assert_eq!(live["scan"]["probed"], 4);
    assert_eq!(live["scan"]["answered"], 1);
    let line = &live["scan"]["lines"][0];
    assert_eq!(line["line"], "1.0");
    assert_eq!(line["answered"][0]["address"], "1.0.1");
    assert_eq!(line["not_answering"].as_array().map(Vec::len), Some(3));

    let traffic = &live["traffic"];
    assert_eq!(traffic["telegrams"], 3, "{traffic}");
    let ga = traffic["per_ga"]
        .as_array()
        .and_then(|a| a.iter().find(|g| g["ga"] == "1/0/2"))
        .ok_or("1/0/2 in the traffic sample")?;
    assert_eq!(ga["repeated"], 1);
    assert!(
        traffic["sender_no_listener"]
            .as_array()
            .is_some_and(|a| a.iter().any(|g| g["ga"] == "7/7/0")),
        "{traffic}"
    );
    assert_eq!(traffic["unknown_sources"][0], "1.0.200");

    // The read-tier promise: nothing the client sent was a group telegram.
    let sent = sent.lock().map_err(|_| "poisoned")?;
    assert!(!sent.is_empty(), "the scan did probe over the tunnel");
    for cemi in sent.iter() {
        assert!(
            matches!(cemi.destination, Destination::Individual(_)),
            "audit --live sent a group telegram: {cemi:?}"
        );
        assert!(
            !matches!(
                cemi.apdu,
                Apdu::GroupValueWrite(_) | Apdu::GroupValueResponse(_)
            ),
            "audit --live sent a group value: {cemi:?}"
        );
    }
    Ok(())
}

#[test]
fn test_audit_live_full_interface_exits_with_distinct_code() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(UdpSocket::bind("127.0.0.1:0"))?;
    let port = gw.local_addr()?.port();
    let mock = rt.spawn(run_mock(gw, Arc::new(Mutex::new(Vec::new())), true));

    let dir = fixture("full")?;
    let gateway = format!("127.0.0.1:{port}");
    let out = bussard(&[
        "audit",
        "--live",
        "--gateway",
        &gateway,
        "--dir",
        dir.to_str().ok_or("path")?,
    ])?;
    mock.abort();
    let _ = std::fs::remove_dir_all(&dir);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "stderr: {stderr}");
    assert!(stderr.contains("E_NO_MORE_CONNECTIONS"), "{stderr}");
    assert!(stderr.contains("Home Assistant"), "{stderr}");
    assert!(stderr.contains("ETS"), "{stderr}");
    Ok(())
}
