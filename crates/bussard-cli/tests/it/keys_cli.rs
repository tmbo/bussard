//! `bussard keys import|export|show` end to end against the committed
//! SYNTHETIC keyring (issue #241). Never a real export.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The synthetic keyring the secure tests share.
const SYNTHETIC: &str = include_str!("../../../../knx-sim/examples/secure/synthetic.knxkeys");

/// Its made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

/// A fresh temp directory holding a model directory and the keyring.
fn setup(tag: &str) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "bussard-keys-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let model = root.join("knx");
    std::fs::create_dir_all(&model)?;
    let keyring = root.join("synthetic.knxkeys");
    std::fs::write(&keyring, SYNTHETIC)?;
    Ok((model, keyring))
}

/// Runs `bussard --dir <model> keys <args>` with the synthetic password.
fn keys(model: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("--dir")
        .arg(model)
        .arg("keys")
        .args(args)
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_KEYRING")
        .output()
}

/// Asserts success and returns stdout.
fn ok(out: &Output) -> Result<String, Box<dyn std::error::Error>> {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout.clone())?)
}

/// No output may carry key bytes or passwords of the fixture.
fn assert_no_secrets(text: &str) {
    for leak in ["tunnel-user-pw", "device-auth-pw", "QkJC", "d3d3", "ERER"] {
        assert!(!text.contains(leak), "leaked {leak}: {text}");
    }
}

#[test]
fn test_keys_import_show_export_round_trip() -> TestResult {
    let (model, keyring) = setup("round")?;
    let path = keyring.to_string_lossy().to_string();

    let first = ok(&keys(&model, &["import", &path])?)?;
    assert!(first.contains("1 added (1.1.10)"), "{first}");
    assert!(first.contains("created the key store"), "{first}");
    assert_no_secrets(&first);
    assert!(model.join("bussard.keys").exists());

    // A second import is a no-op and touches nothing.
    let again = keys(&model, &["--json", "import", &path])?;
    let v: serde_json::Value = serde_json::from_str(&ok(&again)?)?;
    assert_eq!(v["changed"], false);
    assert_eq!(v["written"], false);
    assert_eq!(v["report"]["devices_unchanged"], 1);
    assert!(!model.join("bussard.keys.bak").exists());

    let show = ok(&keys(&model, &["--json", "show"])?)?;
    assert_no_secrets(&show);
    let v: serde_json::Value = serde_json::from_str(&show)?;
    assert_eq!(v["project"], "Synthetic");
    assert_eq!(v["group_keys"], serde_json::json!(["1/2/3"]));
    assert_eq!(v["devices"][0]["address"], "1.1.10");
    assert_eq!(v["devices"][0]["has_tool_key"], true);
    assert_eq!(v["interfaces"][0]["user_id"], 2);

    let text = ok(&keys(&model, &["show"])?)?;
    assert!(text.contains("1.1.10: tool key"), "{text}");
    assert_no_secrets(&text);

    // Export, then import the export into a second store (the reader
    // verifies its signature) and compare the summaries.
    let out = model.parent().ok_or("no parent")?.join("export.knxkeys");
    let out_s = out.to_string_lossy().to_string();
    let exported = ok(&keys(&model, &["export", &out_s])?)?;
    assert!(
        exported.contains("1 device(s), 1 group key(s), 1 interface(s)"),
        "{exported}"
    );
    // Issue #349: the written file is read back, decrypted and compared.
    assert!(
        exported.contains("group addresses carried: 1/2/3"),
        "{exported}"
    );
    assert!(
        exported.contains("verified: read back, decrypted and compared with the key store"),
        "{exported}"
    );
    assert_no_secrets(&exported);
    let json_out = model.parent().ok_or("no parent")?.join("export2.knxkeys");
    let v: serde_json::Value = serde_json::from_str(&ok(&keys(
        &model,
        &["--json", "export", &json_out.to_string_lossy()],
    )?)?)?;
    assert_eq!(v["verified"], true, "{v}");
    assert_eq!(v["group_addresses"], serde_json::json!(["1/2/3"]), "{v}");
    assert_eq!(v["leftovers"], serde_json::json!([]), "{v}");
    let second = model.parent().ok_or("no parent")?.join("knx2");
    std::fs::create_dir_all(&second)?;
    ok(&keys(&second, &["import", &out_s])?)?;
    let v: serde_json::Value = serde_json::from_str(&ok(&keys(&second, &["--json", "show"])?)?)?;
    assert_eq!(v["devices"][0]["address"], "1.1.10");
    assert_eq!(v["group_key_count"], 1);
    assert_eq!(v["has_backbone_key"], true);
    assert_eq!(v["interfaces"][0]["has_password"], true);

    // Refuses to overwrite without --force.
    assert!(!keys(&model, &["export", &out_s])?.status.success());
    ok(&keys(&model, &["export", "--force", &out_s])?)?;
    std::fs::remove_dir_all(model.parent().ok_or("no parent")?)?;
    Ok(())
}

#[test]
fn test_keys_wrong_password_is_refused() -> TestResult {
    let (model, keyring) = setup("wrong")?;
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("--dir")
        .arg(&model)
        .args(["keys", "import"])
        .arg(&keyring)
        .env("BUSSARD_KEYRING_PASSWORD", "not-the-password")
        .output()?;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("wrong keyring password"), "{stderr}");
    assert!(!model.join("bussard.keys").exists());
    std::fs::remove_dir_all(model.parent().ok_or("no parent")?)?;
    Ok(())
}

#[test]
fn test_keys_show_without_a_store_hints_at_import() -> TestResult {
    let (model, _) = setup("empty")?;
    let out = keys(&model, &["show"])?;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bussard keys import"), "{stderr}");
    std::fs::remove_dir_all(model.parent().ok_or("no parent")?)?;
    Ok(())
}

/// Runs `bussard --dir <model> <args>` with the synthetic password.
fn bussard(model: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("--dir")
        .arg(model)
        .args(args)
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_KEYRING")
        .output()
}

/// Issue #331: `bussard groups secure 1/2/3 off` takes the group key out of
/// the store and clears the group's and the linked object's flags; the
/// export then lacks the key, re-importing that export keeps it out, and
/// `bussard undo` restores the flags and the very key.
#[test]
fn test_groups_secure_off_export_reimport_and_undo() -> TestResult {
    let (model, keyring) = setup("unsecure")?;
    let path = keyring.to_string_lossy().to_string();
    ok(&keys(&model, &["import", &path])?)?;
    std::fs::create_dir_all(model.join("devices"))?;
    std::fs::write(
        model.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n",
    )?;
    std::fs::write(
        model.join("groups.toml"),
        "groups = [\n  { address = \"1/2/3\", name = \"Secured level\", dpt = \"5.001\", \
         secure = true },\n]\n",
    )?;
    std::fs::write(
        model.join("devices").join("1.1.10.toml"),
        "address = \"1.1.10\"\nname = \"Secure actuator\"\n\n[security]\nactivated = true\n\n\
         [links]\n22.listen = [\"1/2/3\"]\n",
    )?;
    // A plain push button (no Data Secure) sends on 1/2/3: E035 (#330).
    std::fs::write(
        model.join("devices").join("1.1.40.toml"),
        "address = \"1.1.40\"\nname = \"Meteodata\"\n\n[links]\n1.send = \"1/2/3\"\n",
    )?;
    std::fs::write(
        model.join("bussard.lock"),
        "version = 3\n\n[[device]]\naddress = \"1.1.10\"\nsecure_capable = true\nobjects = \
         [\n  { number = 22, flags = \"CW\", secure = true },\n]\n",
    )?;
    let codes = |model: &Path| -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let out = bussard(model, &["--json", "validate"])?;
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        Ok(v["diagnostics"]
            .as_array()
            .ok_or("no diagnostics")?
            .iter()
            .filter_map(|d| d["code"].as_str().map(str::to_string))
            .collect())
    };
    assert!(codes(&model)?.contains(&"E035".to_string()));
    // The key before the edit, as the export carries it.
    let before = model.join("before.knxkeys");
    ok(&keys(&model, &["export", &before.to_string_lossy()])?)?;
    let original = bussard_project::parse_keyring(&std::fs::read_to_string(&before)?, PASSWORD)?;
    let ga: bussard_model::GroupAddress = "1/2/3".parse()?;
    let key = original
        .group_keys
        .get(&ga)
        .cloned()
        .ok_or("no key before")?;

    let out = ok(&bussard(&model, &["groups", "secure", "1/2/3", "off"])?)?;
    assert_no_secrets(&out);
    assert!(out.contains("Secured level now runs plain"), "{out}");
    assert!(out.contains("object 22 now runs plain"), "{out}");
    assert!(
        out.contains("no longer holds a group key for 1/2/3"),
        "{out}"
    );
    assert!(out.contains("Home Assistant"), "{out}");
    assert!(
        out.contains("`bussard plan <ia>` and `bussard apply <ia>`"),
        "{out}"
    );
    let groups = std::fs::read_to_string(model.join("groups.toml"))?;
    assert!(!groups.contains("secure = true"), "{groups}");
    let lock = std::fs::read_to_string(model.join("bussard.lock"))?;
    assert!(!lock.contains("secure = true"), "{lock}");
    // The plain sender is fine once the GA runs plain.
    assert!(!codes(&model)?.contains(&"E035".to_string()));

    // The export lacks the key; re-importing it does not bring it back.
    let after = model.join("after.knxkeys");
    ok(&keys(&model, &["export", &after.to_string_lossy()])?)?;
    let exported = bussard_project::parse_keyring(&std::fs::read_to_string(&after)?, PASSWORD)?;
    assert!(!exported.group_keys.contains_key(&ga));
    ok(&keys(&model, &["import", &after.to_string_lossy()])?)?;
    let store = bussard_project::KeyStore::load(&model, PASSWORD)?.ok_or("no store")?;
    assert!(store.group_key(ga).is_none());

    // One undo restores all three signals, the very key included.
    let undo = ok(&bussard(&model, &["undo"])?)?;
    assert_no_secrets(&undo);
    assert!(
        undo.contains("holds the group key of 1/2/3 again"),
        "{undo}"
    );
    let store = bussard_project::KeyStore::load(&model, PASSWORD)?.ok_or("no store")?;
    assert_eq!(store.group_key(ga), Some(&key));
    let groups = std::fs::read_to_string(model.join("groups.toml"))?;
    assert!(groups.contains("secure = true"), "{groups}");
    let lock = std::fs::read_to_string(model.join("bussard.lock"))?;
    assert!(lock.contains("secure = true"), "{lock}");
    let _ = std::fs::remove_dir_all(model.parent().ok_or("no parent")?);
    Ok(())
}

/// Runs `bussard --dir <model> keys add-certificate <args>` with `input` on
/// stdin and `password` (or none) in the environment.
fn add_certificate(
    model: &Path,
    args: &[&str],
    input: &str,
    password: Option<&str>,
) -> std::io::Result<Output> {
    use std::io::Write as _;
    let mut command = Command::new(env!("CARGO_BIN_EXE_bussard"));
    command
        .arg("--dir")
        .arg(model)
        .arg("keys")
        .args(args)
        .env_remove("BUSSARD_KEYRING")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    match password {
        Some(pw) => command.env("BUSSARD_KEYRING_PASSWORD", pw),
        None => command.env_remove("BUSSARD_KEYRING_PASSWORD"),
    };
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    child.wait_with_output()
}

/// The first certificate vector of `dev/enroll/vectors-v1.json` (synthetic:
/// serial 00FA01020304, FDSK A0..AF).
const LABEL: &str = "AD5ACA-QDASQK-DIVDUS-S2NJ5I-VGVKXL-FNV2X5";

/// The second vector (serial 0083A1B2C3D4, an all-zero FDSK).
const LABEL_ZERO: &str = "ACB2DM-WD2QAA-AAAAAA-AAAAAA-AAAAAA-AAAAAG";

/// The same serial as [`LABEL`] with another (synthetic) FDSK, built with the
/// codec so the check matches.
fn conflicting_label() -> String {
    bussard_secure::Certificate::encode(
        &[0x00, 0xFA, 0x01, 0x02, 0x03, 0x04],
        &bussard_secure::Key16::new([0x5A; 16]),
    )
}

#[test]
fn test_keys_add_certificate_stdin_statuses() -> TestResult {
    let (model, _) = setup("addcert")?;
    let input = format!(
        "{}\n\n{LABEL}\n{}\nNOT-A-LABEL\n",
        LABEL.to_lowercase(),
        conflicting_label()
    );
    let out = add_certificate(
        &model,
        &["--json", "add-certificate", "--stdin"],
        &input,
        Some(PASSWORD),
    )?;
    // A conflict and an invalid label fail the command; the rest is saved.
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout.clone())?;
    let stderr = String::from_utf8(out.stderr.clone())?;
    for text in [&stdout, &stderr] {
        assert!(!text.to_ascii_uppercase().contains("A0A1A2"), "{text}");
        assert!(!text.contains("QDASQK"), "{text}");
    }
    let v: serde_json::Value = serde_json::from_str(&stdout)?;
    let statuses: Vec<&str> = v["results"]
        .as_array()
        .ok_or("no results")?
        .iter()
        .filter_map(|r| r["status"].as_str())
        .collect();
    assert_eq!(
        statuses,
        ["unassigned", "already_stored", "conflict", "invalid"]
    );
    assert_eq!(v["results"][0]["serial"], "00FA01020304");

    let show = ok(&keys(&model, &["show"])?)?;
    assert!(
        show.contains("certificates without a device (serial numbers): 00FA01020304"),
        "{show}"
    );

    // A label for a device the store knows by serial is stored on it.
    let mut store = bussard_project::KeyStore::load(&model, PASSWORD)?.ok_or("no store")?;
    store.devices.entry("1.1.7".parse()?).or_default().serial = Some("0083A1B2C3D4".parse()?);
    store.save(&model, PASSWORD)?;
    let out = add_certificate(
        &model,
        &["add-certificate", "--stdin"],
        &format!("{LABEL_ZERO}\n"),
        Some(PASSWORD),
    )?;
    let text = ok(&out)?;
    assert!(text.contains("0083A1B2C3D4 1.1.7: stored"), "{text}");
    let store = bussard_project::KeyStore::load(&model, PASSWORD)?.ok_or("no store")?;
    let device = store.devices.get(&"1.1.7".parse()?).ok_or("no 1.1.7")?;
    assert_eq!(device.fdsk, Some(bussard_secure::Key16::new([0; 16])));
    Ok(())
}

#[test]
fn test_keys_add_certificate_refuses_before_reading() -> TestResult {
    let (model, _) = setup("addcert-refuse")?;
    // No password: refused, nothing written.
    let out = add_certificate(
        &model,
        &["add-certificate", "--stdin"],
        &format!("{LABEL}\n"),
        None,
    )?;
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)?.contains("BUSSARD_KEYRING_PASSWORD"));
    assert!(!model.join("bussard.keys").exists());
    // Not a terminal and no --stdin: refused, never read.
    let out = add_certificate(
        &model,
        &["add-certificate"],
        &format!("{LABEL}\n"),
        Some(PASSWORD),
    )?;
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)?.contains("--stdin"));
    assert!(!model.join("bussard.keys").exists());
    Ok(())
}
