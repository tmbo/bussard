//! End-to-end test of `bussard learn` against an in-process mock KNX gateway
//! (issue #95).
//!
//! The `bussard-testkit` mock gateway pushes a repeating set of group telegrams from a device the
//! fixture model knows, and counts every TUNNELING_REQUEST the client sends. A
//! scripted `--yes` session names and types three group addresses; afterwards
//! the model must pass `bussard validate` with no `W011` (no DPT) warning for
//! any of them, and the gateway must have received **zero** tunnelling requests:
//! learn mode never transmits.
//!
//! Everything binds `127.0.0.1:0`, so no real gateway is ever contacted.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_testkit::{MockGateway, TestResult, ga, ia};
use bussard_transport::cemi::{CemiFrame, MessageCode};

const CHANNEL: u8 = 0x21;

/// The device the fixture model knows; every pushed telegram comes from it.
const SENDER: &str = "1.1.30";

/// The telegrams the mock bus carries, pushed in a loop.
fn telegrams() -> TestResult<Vec<(GroupAddress, Vec<u8>)>> {
    Ok(vec![
        // A 1-bit switch on a GA the model already links to com object 3.
        (ga("1/0/1")?, vec![0x01]),
        // A byte-wide value that reads as a percentage.
        (ga("1/0/2")?, vec![0x32]),
        // 21.5 °C as a 2-byte float.
        (ga("1/0/3")?, vec![0x0c, 0x33]),
    ])
}

/// Pushes the fixture telegrams to the connected client, over and over from
/// the first CONNECT on, so the session sees each group address whenever it
/// starts waiting for it. Ends when the gateway has stopped.
async fn push_telegrams(gw: Arc<MockGateway>, frames: Vec<CemiFrame>) {
    if !gw
        .wait_until(Duration::from_secs(60), |s| s.connects > 0)
        .await
    {
        return;
    }
    loop {
        for frame in &frames {
            if gw.push(frame.clone()).is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    }
}

/// Writes the fixture model: one device the sender maps to, with a channel, two
/// transmit-capable com objects, and a link for the first group address.
fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(dir.join("groups.toml"), "groups: {}\n")?;
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
fn learn_names_and_types_group_addresses_without_transmitting() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    // The mock gateway answers the KNXnet/IP handshake and counts the
    // tunnelling requests it receives; a pusher task plays the bus traffic.
    let gw = Arc::new(
        rt.block_on(
            MockGateway::builder()
                .channel(CHANNEL)
                .idle_timeout(Duration::from_secs(60))
                .start(),
        )?,
    );
    let port = gw.port();
    let source = ia(SENDER)?;
    let frames = telegrams()?
        .into_iter()
        .map(|(ga, payload)| {
            let mut cemi = CemiFrame::group_write_packed(ga, source, &payload);
            // A bus indication, not our own request echoing back.
            cemi.message_code = MessageCode::LDataInd;
            cemi
        })
        .collect();
    let pusher = rt.spawn(push_telegrams(Arc::clone(&gw), frames));

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
        gw.stats().requests,
        0,
        "learn transmitted on the bus.\nstderr:\n{stderr}"
    );

    // Every target was named and typed in groups.toml.
    let groups = std::fs::read_to_string(model_dir.join("groups.toml"))?;
    for ga in ["1/0/1", "1/0/2", "1/0/3"] {
        assert!(
            groups.contains(ga),
            "{ga} missing from groups.toml:\n{groups}"
        );
    }
    assert!(
        groups.contains("1.001") && groups.contains("5.001") && groups.contains("9.001"),
        "expected the inferred DPTs in groups.toml:\n{groups}"
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

    pusher.abort();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}
