//! End-to-end tests of `bussard audit` (issue #93) and its full-interface exit
//! code (issue #105).
//!
//! The static tests run on a copy of the small-installation example model. The
//! live test runs against an in-process mock KNXnet/IP gateway on 127.0.0.1
//! that advertises two tunnel slots, pushes a few group telegrams during the
//! traffic window, answers management probes for one device, and records every
//! frame the client sends: the test proves `--live` never transmits a group
//! telegram.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::wire::description_response_body;
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, MessageCode};
use serde_json::Value;

const CHANNEL: u8 = 0x21;

/// Copies the small-installation example model into a fresh temp directory.
fn fixture(tag: &str) -> TestResult<PathBuf> {
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

/// Starts the live mock on `rt`: a gateway that advertises two tunnel slots
/// (one in use), answers management probes for the single present device
/// 1.0.1, records every frame the client sends, and, once the long-lived bus
/// session has been up briefly, pushes traffic: two identical writes 50 ms
/// apart (a repetition) and one to a GA the model has no listener for, from a
/// source the model does not know. `refuse` answers every CONNECT with 0x24.
fn start_mock(rt: &tokio::runtime::Runtime, refuse: bool) -> TestResult<MockGateway> {
    let src = ia("1.0.1")?;
    let stranger = IndividualAddress::from_raw(0x10C8); // 1.0.200
    let ga1: GroupAddress = "1/0/2".parse()?;
    let ga_orphan = GroupAddress::from_raw(0x3F00); // 7/7/0
    let mut w = CemiFrame::group_write_packed(ga1, src, &[1]);
    w.message_code = MessageCode::LDataInd;
    let mut o = CemiFrame::group_write_packed(ga_orphan, stranger, &[0]);
    o.message_code = MessageCode::LDataInd;

    // The present device: ACKs every numbered request and answers authorize and
    // the descriptor read.
    let device = MockDevice::new(src).with_hook(|_, code, _| {
        Some(match code {
            apci::A_AUTHORIZE_REQUEST => Reaction::Answer(apci::A_AUTHORIZE_RESPONSE, vec![0x00]),
            apci::A_DEVICE_DESCRIPTOR_READ => {
                Reaction::Answer(apci::A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0])
            }
            _ => Reaction::Ack,
        })
    });
    let mut builder = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .description(description_response_body("Mock Gate", 2, 1))
        .push_once_after_connect(Duration::from_millis(400), w.clone())
        .push_once_after_connect(Duration::from_millis(450), w)
        .push_once_after_connect(Duration::from_millis(450), o)
        .device(device);
    if refuse {
        builder = builder.refuse_connect(0x24);
    }
    Ok(rt.block_on(builder.start())?)
}

#[test]
fn test_audit_live_reports_gateway_traffic_scan_and_never_writes_a_group() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let mock = start_mock(&rt, false)?;
    let port = mock.port();

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
    let sent = mock.sent()?;
    drop(mock);
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
    let mock = start_mock(&rt, true)?;
    let port = mock.port();

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
    drop(mock);
    let _ = std::fs::remove_dir_all(&dir);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "stderr: {stderr}");
    assert!(stderr.contains("E_NO_MORE_CONNECTIONS"), "{stderr}");
    assert!(stderr.contains("Home Assistant"), "{stderr}");
    assert!(stderr.contains("ETS"), "{stderr}");
    Ok(())
}

/// A command on the reconnecting bus actor (here `read`) also reports a full
/// interface with its own message and exit code, not as a generic timeout.
#[test]
fn test_read_full_interface_exits_with_distinct_code() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let mock = start_mock(&rt, true)?;
    let port = mock.port();

    let dir = fixture("read-full")?;
    let gateway = format!("127.0.0.1:{port}");
    let out = bussard(&[
        "read",
        "1/0/2",
        "--gateway",
        &gateway,
        "--dir",
        dir.to_str().ok_or("path")?,
    ])?;
    drop(mock);
    let _ = std::fs::remove_dir_all(&dir);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "stderr: {stderr}");
    assert!(stderr.contains("E_NO_MORE_CONNECTIONS"), "{stderr}");
    Ok(())
}
