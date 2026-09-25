//! `bussard learn` with KNX Data Secure group telegrams against a mock gateway
//! (issue #204).
//!
//! The keyring is the committed SYNTHETIC `knx-sim/examples/secure/synthetic.knxkeys`
//! (made-up password, one group key for 1/2/3), the same one
//! `secure_group_mock.rs` uses. The mock gateway binds 127.0.0.1 only and every
//! run gets an explicit loopback `--gateway`. The test decrypts the keyring
//! itself to play the secured sender, and never prints a key.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_secure::{Key16, SecurityAlgorithm, Sequence, encode_group};
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

/// A secured `GroupValueWrite` of `value` from 1.1.10 to `dest`, as an
/// `L_Data.ind`.
fn secured_write(key: &Key16, dest: GroupAddress, seq: u64, value: u8) -> TestResult<CemiFrame> {
    let source = ia("1.1.10")?;
    let apdu = Apdu::GroupValueWrite(GroupData::Large(vec![value]));
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

/// A plain one-byte `GroupValueWrite` from 1.1.11 to `dest`.
fn plain_write(dest: GroupAddress, value: u8) -> TestResult<CemiFrame> {
    let mut frame = CemiFrame::group_write(dest, ia("1.1.11")?, &[value], false);
    frame.message_code = MessageCode::LDataInd;
    Ok(frame)
}

/// Pushes `frames` to the connected client over and over from the first
/// CONNECT on. Ends when the gateway has stopped.
async fn push_loop(gw: Arc<MockGateway>, frames: Vec<CemiFrame>) {
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

/// A fresh model directory: 1/2/3 and 1/2/4 with placeholder names and no
/// DPT. `keyring_in_config` sets `connection.keyring` to the synthetic keyring.
fn model_dir(tag: &str, port: u16, keyring_in_config: bool) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-learn-secure-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    let mut config =
        format!("[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:{port}\"\n");
    if keyring_in_config {
        let keyring = keyring_path();
        let keyring = keyring.to_str().ok_or("keyring path is not UTF-8")?;
        config.push_str(&format!("keyring = {keyring:?}\n"));
    }
    std::fs::write(dir.join("bussard.toml"), config)?;
    std::fs::write(
        dir.join("groups.toml"),
        "project = \"learn-secure\"\n\ngroups = [\n  \
         { address = \"1/2/3\", name = \"GA 1/2/3\" },\n  \
         { address = \"1/2/4\", name = \"GA 1/2/4\" },\n]\n",
    )?;
    Ok(dir)
}

/// Runs `bussard learn --yes` on the given GAs against the mock gateway.
fn learn(dir: &Path, port: u16, gas: &[&str], extra: &[String]) -> TestResult<Output> {
    let mut args: Vec<String> = vec!["learn".into()];
    for g in gas {
        args.push("--ga".into());
        args.push((*g).to_string());
    }
    args.extend([
        "--yes".to_string(),
        "--timeout".to_string(),
        "15".to_string(),
        "--dir".to_string(),
        dir.to_str().ok_or("dir is not UTF-8")?.to_string(),
        "--gateway".to_string(),
        format!("127.0.0.1:{port}"),
    ]);
    args.extend(extra.iter().cloned());
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&args)
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

/// The `groups.toml` line for `address`, or an error naming the file.
fn group_line(groups: &str, address: &str) -> TestResult<String> {
    groups
        .lines()
        .find(|l| l.contains(&format!("\"{address}\"")))
        .map(str::to_string)
        .ok_or_else(|| format!("{address} missing from groups.toml:\n{groups}").into())
}

/// Starts a mock gateway replaying `frames`, runs one learn session, and
/// returns the gateway, the output and the resulting `groups.toml`.
fn session(
    tag: &str,
    frames: Vec<CemiFrame>,
    keyring_in_config: bool,
    gas: &[&str],
    extra: &[String],
) -> TestResult<(Arc<MockGateway>, Output, String)> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = Arc::new(
        rt.block_on(
            MockGateway::builder()
                .idle_timeout(Duration::from_secs(60))
                .start(),
        )?,
    );
    let pusher = rt.spawn(push_loop(Arc::clone(&gw), frames));
    let dir = model_dir(tag, gw.port(), keyring_in_config)?;
    let out = learn(&dir, gw.port(), gas, extra)?;
    pusher.abort();
    let groups = std::fs::read_to_string(dir.join("groups.toml"))?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok((gw, out, groups))
}

#[test]
fn test_learn_keyring_decrypts_and_marks_the_group_secure() -> TestResult {
    let key = group_key()?;
    let target = ga("1/2/3")?;
    // Every frame repeats one sequence number, so from the second telegram on
    // the freshness check flags a replay; learning 1/2/3 twice guarantees the
    // second observation carries the warning.
    let frames = vec![secured_write(&key, target, 9_000, 0x80)?];
    let keyring = keyring_path().to_string_lossy().to_string();
    let (gw, out, groups) = session(
        "flag",
        frames,
        false,
        &["1/2/3", "1/2/3"],
        &["--keyring".to_string(), keyring],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(gw.stats().requests, 0, "learn transmitted:\n{stderr}");
    assert!(stderr.contains("verified and decrypted"), "{stderr}");
    // The decrypted inner payload (0x80) was learned, not the ciphertext.
    assert!(stderr.contains("payload 80 (1 byte(s))"), "{stderr}");
    assert!(stderr.contains("not above the last seen 9000"), "{stderr}");
    assert!(stdout.contains("secured)"), "{stdout}");
    let line = group_line(&groups, "1/2/3")?;
    assert!(line.contains("secure = true"), "{groups}");
    assert!(line.contains("dpt = \"5."), "{groups}");
    Ok(())
}

#[test]
fn test_learn_uses_the_config_keyring_by_default() -> TestResult {
    let key = group_key()?;
    let frames = vec![
        secured_write(&key, ga("1/2/3")?, 10_000, 0x40)?,
        plain_write(ga("1/2/4")?, 0x40)?,
    ];
    let (gw, out, groups) = session("config", frames, true, &["1/2/3", "1/2/4"], &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(gw.stats().requests, 0, "learn transmitted:\n{stderr}");
    assert!(stderr.contains("keyring: 1 group key(s)"), "{stderr}");
    assert!(
        group_line(&groups, "1/2/3")?.contains("secure = true"),
        "{groups}"
    );
    // A plain GA learned in the same session stays plain.
    let plain = group_line(&groups, "1/2/4")?;
    assert!(plain.contains("dpt = "), "{groups}");
    assert!(!plain.contains("secure"), "{groups}");
    Ok(())
}

#[test]
fn test_learn_without_keyring_skips_secured_and_learns_plain_unchanged() -> TestResult {
    let key = group_key()?;
    let frames = vec![
        secured_write(&key, ga("1/2/3")?, 11_000, 0x32)?,
        // 0x32 reads as a percentage, as in `learn_mock.rs`.
        plain_write(ga("1/2/4")?, 0x32)?,
    ];
    let (gw, out, groups) = session("nokey", frames, false, &["1/2/3", "1/2/4"], &[])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(gw.stats().requests, 0, "learn transmitted:\n{stderr}");
    // The secured telegram is reported with the way to decrypt it, not guessed.
    assert!(stderr.contains("--keyring"), "{stderr}");
    let secured = group_line(&groups, "1/2/3")?;
    assert!(!secured.contains("dpt"), "{groups}");
    assert!(!secured.contains("secure"), "{groups}");
    // The plain telegram learns exactly as before: a DPT, no secure flag, and
    // the stdout line without the secured marker.
    let plain = group_line(&groups, "1/2/4")?;
    assert!(plain.contains("dpt = \"5.001\""), "{groups}");
    assert!(!plain.contains("secure"), "{groups}");
    assert!(
        stdout.contains("1/2/4") && !stdout.contains("secured"),
        "{stdout}"
    );
    Ok(())
}
