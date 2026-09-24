//! KNX Data Secure group communication end to end against a mock gateway
//! (issue #172): `read`, `write` and `monitor` with `--keyring`.
//!
//! The keyring is the committed SYNTHETIC `knx-sim/examples/secure/synthetic.knxkeys`
//! (made-up password, one group key for 1/2/3). The mock gateway binds
//! 127.0.0.1 only; every command gets an explicit loopback `--gateway`. The
//! test decrypts the keyring itself to play the secured device on the mock
//! line, and never prints a key.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_secure::{Key16, SecurityAlgorithm, Sequence, decode_group, encode_group};
use bussard_testkit::{MockGateway, TestResult, ga, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, GroupData, MessageCode};

/// The synthetic keyring's made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

/// The committed synthetic keyring (one group key, for 1/2/3).
fn keyring_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knx-sim/examples/secure/synthetic.knxkeys")
}

/// The group key of 1/2/3 in the synthetic keyring.
fn group_key() -> TestResult<Key16> {
    let xml = std::fs::read_to_string(keyring_path())?;
    let keyring = bussard_project::parse_keyring(&xml, PASSWORD)?;
    Ok(keyring
        .group_keys
        .get(&ga("1/2/3")?)
        .ok_or("the synthetic keyring has no key for 1/2/3")?
        .clone())
}

/// A model with the secured 1/2/3, the plain 1/2/4 (both DPT 5.001) and the
/// secured-but-keyless 1/2/9.
fn model_dir(tag: &str, port: u16) -> TestResult<PathBuf> {
    let dir =
        std::env::temp_dir().join(format!("bussard-secure-group-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        format!("connection:\n  transport: tunnel\n  gateway: 127.0.0.1:{port}\n"),
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "project: secure\ngroups:\n  1/2/3:\n    name: Secured dimming\n    dpt: '5.001'\n    \
         secure: true\n  1/2/4:\n    name: Plain value\n    dpt: '5.001'\n  1/2/9:\n    \
         name: Secured without key\n    dpt: '5.001'\n    secure: true\n",
    )?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    Ok(dir)
}

/// Runs `bussard <args>` with the keyring password set and no TTY.
async fn bussard(args: Vec<String>) -> TestResult<Output> {
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(&args)
            .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .stdin(Stdio::null())
            .output()
    })
    .await??;
    Ok(out)
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// A secured group telegram from `src` to `dest` carrying `apdu`, as an
/// `L_Data.ind`.
fn secured_ind(
    key: &Key16,
    src: &str,
    dest: GroupAddress,
    seq: u64,
    apdu: &Apdu,
) -> TestResult<CemiFrame> {
    let source = ia(src)?;
    let asdu = encode_group(
        key,
        SecurityAlgorithm::AuthenticationEncryption,
        Sequence::new(seq),
        source.raw(),
        dest.raw(),
        &apdu.group_tpdu_bytes(),
    )?;
    let mut frame = CemiFrame::group_secure(dest, source, asdu);
    frame.message_code = MessageCode::LDataInd;
    Ok(frame)
}

/// The inner APDU of a secured frame the client sent, verified under `key`.
fn unwrap_sent(frame: &CemiFrame, key: &Key16) -> Option<Apdu> {
    let dest = frame.group_destination()?;
    let plain = decode_group(key, frame.secure_asdu()?, frame.source.raw(), dest.raw()).ok()?;
    Apdu::from_group_tpdu(&plain.apdu).ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_read_secured_ga_is_sealed_and_the_response_verified() -> TestResult {
    let key = group_key()?;
    let device_key = key.clone();
    let target = ga("1/2/3")?;
    // The secured device on the line: answer a verified GroupValueRead with a
    // secured GroupValueResponse of 0x80 (50 %).
    let gw = MockGateway::builder()
        .respond(move |frame| {
            if unwrap_sent(frame, &device_key) != Some(Apdu::GroupValueRead) {
                return Vec::new();
            }
            let response = Apdu::GroupValueResponse(GroupData::Large(vec![0x80]));
            secured_ind(&device_key, "1.1.10", target, 5_000, &response)
                .map(|f| vec![f])
                .unwrap_or_default()
        })
        .start()
        .await?;
    let dir = model_dir("read", gw.port())?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let keyring = keyring_path();
    let out = bussard(args(&[
        "read",
        "1/2/3",
        "--dir",
        &dir.to_string_lossy(),
        "--keyring",
        &keyring.to_string_lossy(),
        "--gateway",
        &gateway,
    ]))
    .await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("(5.001)"), "{stdout}");
    assert!(stdout.starts_with("50"), "0x80 is 50 %: {stdout}");
    assert!(stderr.contains("secured"), "{stderr}");
    // What went on the wire: one A_SecureData to 1/2/3, no plain read.
    let sent = gw.sent()?;
    assert!(
        sent.iter()
            .any(|f| unwrap_sent(f, &key) == Some(Apdu::GroupValueRead)),
        "no secured GroupValueRead was sent: {sent:?}"
    );
    assert!(
        !sent.iter().any(|f| f.apdu == Apdu::GroupValueRead),
        "a plain read of a secured GA went out"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_read_secured_ga_ignores_a_plain_or_forged_response() -> TestResult {
    let key = group_key()?;
    let device_key = key.clone();
    let target = ga("1/2/3")?;
    let device = ia("1.1.10")?;
    // A misbehaving line: a plain response and one under the wrong key. Neither
    // may be taken for the value.
    let gw = MockGateway::builder()
        .respond(move |frame| {
            if unwrap_sent(frame, &device_key).is_none() {
                return Vec::new();
            }
            let response = Apdu::GroupValueResponse(GroupData::Large(vec![0x80]));
            let mut plain = CemiFrame::group_response(target, device, &[0x80], false);
            plain.message_code = MessageCode::LDataInd;
            let mut out = vec![plain];
            if let Ok(forged) = secured_ind(&Key16::new([0x33; 16]), "1.1.10", target, 9, &response)
            {
                out.push(forged);
            }
            out
        })
        .start()
        .await?;
    let dir = model_dir("read-forged", gw.port())?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let keyring = keyring_path();
    let out = bussard(args(&[
        "read",
        "1/2/3",
        "--dir",
        &dir.to_string_lossy(),
        "--keyring",
        &keyring.to_string_lossy(),
        "--gateway",
        &gateway,
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must time out: {stderr}");
    assert!(stderr.contains("no verified secured response"), "{stderr}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_read_secured_ga_without_keyring_is_refused_with_a_hint() -> TestResult {
    // Refused before connecting: the port is never contacted.
    let dir = model_dir("read-nokey", 9)?;
    let out = bussard(args(&[
        "read",
        "1/2/3",
        "--dir",
        &dir.to_string_lossy(),
        "--gateway",
        "127.0.0.1:9",
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("secured") && stderr.contains("--keyring"),
        "{stderr}"
    );
    // With the keyring, a secured GA it has no key for is refused too.
    let keyring = keyring_path();
    let out = bussard(args(&[
        "read",
        "1/2/9",
        "--dir",
        &dir.to_string_lossy(),
        "--keyring",
        &keyring.to_string_lossy(),
        "--gateway",
        "127.0.0.1:9",
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("has no group key"), "{stderr}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_write_secured_ga_is_sealed_under_the_group_key() -> TestResult {
    let key = group_key()?;
    let gw = MockGateway::builder().start().await?;
    let dir = model_dir("write", gw.port())?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let keyring = keyring_path();
    let out = bussard(args(&[
        "write",
        "1/2/3",
        "50%",
        "--yes",
        "--dir",
        &dir.to_string_lossy(),
        "--keyring",
        &keyring.to_string_lossy(),
        "--gateway",
        &gateway,
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("secured"), "{stderr}");
    let sent = gw.sent()?;
    let secured: Vec<Apdu> = sent.iter().filter_map(|f| unwrap_sent(f, &key)).collect();
    assert_eq!(
        secured,
        vec![Apdu::GroupValueWrite(GroupData::Large(vec![0x80]))],
        "exactly one secured write of 0x80"
    );
    // The sealed frame is a T_Data_Group from the tunnel address.
    let frame = sent
        .iter()
        .find(|f| f.secure_asdu().is_some())
        .ok_or("no secured frame")?;
    assert_eq!(frame.source, ia("1.1.255")?);
    assert_eq!(frame.secure_asdu().and_then(|a| a.first()), Some(&0x10));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_write_plain_ga_with_keyring_is_byte_identical() -> TestResult {
    let gw = MockGateway::builder().start().await?;
    let dir = model_dir("write-plain", gw.port())?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let keyring = keyring_path();
    let out = bussard(args(&[
        "write",
        "1/2/4",
        "50%",
        "--yes",
        "--dir",
        &dir.to_string_lossy(),
        "--keyring",
        &keyring.to_string_lossy(),
        "--gateway",
        &gateway,
    ]))
    .await?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sent = gw.sent()?;
    let expected = CemiFrame::group_write(ga("1/2/4")?, ia("1.1.255")?, &[0x80], false).encode();
    assert_eq!(
        sent.iter().map(CemiFrame::encode).collect::<Vec<_>>(),
        vec![expected],
        "the plain path must not change with a keyring"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_write_secured_ga_without_keyring_is_refused() -> TestResult {
    let dir = model_dir("write-nokey", 9)?;
    let out = bussard(args(&[
        "write",
        "1/2/3",
        "50%",
        "--yes",
        "--dir",
        &dir.to_string_lossy(),
        "--gateway",
        "127.0.0.1:9",
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("--keyring"), "{stderr}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_monitor_keyring_decrypts_and_flags_secured_telegrams() -> TestResult {
    let key = group_key()?;
    let target = ga("1/2/3")?;
    let write = Apdu::GroupValueWrite(GroupData::Large(vec![0x80]));
    let good = secured_ind(&key, "1.1.10", target, 7_000, &write)?;
    let replay = secured_ind(&key, "1.1.10", target, 7_000, &write)?;
    let forged = secured_ind(&Key16::new([0x33; 16]), "1.1.10", target, 7_001, &write)?;
    let mut plain = CemiFrame::group_write(ga("1/2/4")?, ia("1.1.11")?, &[0x80], false);
    plain.message_code = MessageCode::LDataInd;
    let gw = MockGateway::builder()
        .push_after_connect(Duration::from_millis(300), good)
        .push_after_connect(Duration::from_millis(350), replay)
        .push_after_connect(Duration::from_millis(400), forged)
        .push_after_connect(Duration::from_millis(450), plain)
        .start()
        .await?;
    let dir = model_dir("monitor", gw.port())?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "monitor",
            "--json",
            "--dir",
            &dir.to_string_lossy(),
            "--keyring",
            &keyring_path().to_string_lossy(),
            "--gateway",
            &gateway,
        ])
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut lines = Vec::new();
    while lines.len() < 4 {
        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(line) => lines.push(serde_json::from_str::<serde_json::Value>(&line)?),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(lines.len(), 4, "expected four telegrams, got {lines:?}");

    // Verified: decoded like a plain write, flagged secured.
    assert_eq!(lines[0]["destination"], "1/2/3");
    assert_eq!(lines[0]["apci"], "write");
    assert_eq!(lines[0]["payload"], "80");
    assert_eq!(lines[0]["dpt"], "5.001");
    assert_eq!(lines[0]["secured"], true);
    assert_eq!(lines[0]["secure_status"], "ok");
    assert_eq!(lines[0]["secure_seq"], 7_000);
    assert_eq!(lines[0]["secure_warning"], serde_json::Value::Null);
    // The same sequence again: still decoded, with an advisory warning.
    assert_eq!(lines[1]["secured"], true);
    assert_eq!(lines[1]["value"], lines[0]["value"]);
    assert!(
        lines[1]["secure_warning"]
            .as_str()
            .is_some_and(|w| w.contains("not above the last seen 7000")),
        "{:?}",
        lines[1]
    );
    // A MAC failure keeps the raw bytes.
    assert_eq!(lines[2]["secured"], false);
    assert_eq!(lines[2]["secure_status"], "mac_failed");
    assert!(
        lines[2]["secure_raw"]
            .as_str()
            .is_some_and(|r| r.starts_with("10"))
    );
    // Plain traffic carries no secure fields.
    assert_eq!(lines[3]["destination"], "1/2/4");
    assert!(lines[3].get("secured").is_none(), "{:?}", lines[3]);
    Ok(())
}
