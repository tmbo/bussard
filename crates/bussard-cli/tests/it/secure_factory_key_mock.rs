//! Issue #532: a Data Secure device that was reset to default answers only
//! under its factory default setup key (FDSK). `describe` and `apply` with
//! a key store that holds the device's tool key AND its FDSK try one more
//! S-A_Sync under the FDSK when the tool key's go unanswered, name the state
//! and refuse to go on; a device the model does not mark activated that
//! refuses plain access is tried under the FDSK before the "export a
//! keyring" advice.
//!
//! All keys are SYNTHETIC. The mock binds 127.0.0.1 and every run passes an
//! explicit loopback `--gateway`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_project::KeyStore;
use bussard_project::keystore::StoreDevice;
use bussard_secure::Key16;
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};

/// The key store's made-up password.
const PASSWORD: &str = "synthetic-store-password";
/// The synthetic tool key the store holds for 1.1.10.
const TOOL_KEY: [u8; 16] = [0x11; 16];
/// The synthetic FDSK the store holds for 1.1.10.
const FDSK: [u8; 16] = [0x24; 16];

/// A model directory with 1.1.10 (`activated` as given) and a key store that
/// holds `tool_key` (when given) and the FDSK for it.
fn model_dir(tag: &str, activated: bool, tool_key: Option<[u8; 16]>) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-fdsk-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Status\", dpt = \"1.001\" },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.10.toml"),
        format!(
            "address = \"1.1.10\"\nname = \"Secure actuator\"\n\n[security]\nactivated = \
             {activated}\n\n[links]\n20.send = \"1/2/0\"\n"
        ),
    )?;
    let mut store = KeyStore::new("Synthetic");
    store.devices.insert(
        ia("1.1.10")?,
        StoreDevice {
            tool_key: tool_key.map(Key16::new),
            fdsk: Some(Key16::new(FDSK)),
            ..StoreDevice::default()
        },
    );
    store.save(&dir, PASSWORD)?;
    Ok(dir)
}

/// Runs `bussard <args> --dir <dir> --gateway <mock> --keyring <store>`
/// against a device that answers Data Secure under the FDSK only.
fn run(dir: &Path, args: &[&str]) -> TestResult<Output> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x5A)
            .idle_timeout(Duration::from_secs(60))
            .keep_serving()
            .device(MockDevice::system_b(ia("1.1.10")?).with_data_secure(FDSK))
            .start(),
    )?;
    let store = KeyStore::path(dir);
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
        .env("BUSSARD_ADDRESS_PROBE_MS", "200")
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .args(args)
        .arg("--dir")
        .arg(dir)
        .arg("--gateway")
        .arg(format!("127.0.0.1:{}", gw.port()))
        .arg("--keyring")
        .arg(&store)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    drop(gw);
    Ok(out)
}

#[test]
fn test_describe_names_a_device_reset_to_its_factory_key() -> TestResult {
    let dir = model_dir("describe", true, Some(TOOL_KEY))?;
    let out = run(&dir, &["describe", "1.1.10"]);
    let _ = std::fs::remove_dir_all(&dir);
    let out = out?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("1.1.10 is back on its factory key (FDSK)")
            && stderr.contains("reset to default"),
        "{stderr}"
    );
    assert!(!stderr.contains("not this device's key"), "{stderr}");
    Ok(())
}

#[test]
fn test_apply_refuses_a_device_reset_to_its_factory_key() -> TestResult {
    let dir = model_dir("apply", true, Some(TOOL_KEY))?;
    let out = run(&dir, &["apply", "1.1.10", "--yes"]);
    let _ = std::fs::remove_dir_all(&dir);
    let out = out?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("is back on its factory key (FDSK)"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn test_describe_tries_the_factory_key_before_asking_for_a_keyring() -> TestResult {
    // Not activated in the model and no tool key in the store: plain access
    // first, then the FDSK.
    let dir = model_dir("converse", false, None)?;
    let out = run(&dir, &["describe", "1.1.10"]);
    let _ = std::fs::remove_dir_all(&dir);
    let out = out?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("answers a secured read under its factory key (FDSK)"),
        "{stderr}"
    );
    assert!(!stderr.contains("--keyring <file.knxkeys>"), "{stderr}");
    Ok(())
}

/// Issue #571: `knx_describe_device` takes the same FDSK fallback as
/// `bussard describe` (the shared service function): a device without a tool
/// key that refuses the plain walk and answers under its FDSK is named, with
/// `factory_key: true`, instead of an empty object list.
#[test]
fn test_mcp_describe_tries_the_factory_key_like_the_cli() -> TestResult {
    let dir = model_dir("mcp-converse", false, None)?;
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x5C)
            .idle_timeout(Duration::from_secs(60))
            .keep_serving()
            .device(MockDevice::system_b(ia("1.1.10")?).with_data_secure(FDSK))
            .start(),
    )?;
    let described = (|| {
        let mut server = crate::mcp_stdio_client::McpServer::start(
            &dir,
            gw.port(),
            &KeyStore::path(&dir),
            PASSWORD,
            &["--no-model-edits"],
        )?;
        server.call_when_connected(
            "knx_describe_device",
            serde_json::json!({"address": "1.1.10"}),
            50,
        )
    })();
    drop(gw);
    let _ = std::fs::remove_dir_all(&dir);
    let described = described?;
    assert_eq!(described["ok"], false, "{described}");
    assert_eq!(described["factory_key"], true, "{described}");
    let reason = described["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("answers a secured read under its factory key (FDSK)"),
        "{described}"
    );
    Ok(())
}
