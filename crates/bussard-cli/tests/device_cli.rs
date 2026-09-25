//! `bussard device <ADDRESS> [<CHANNEL>]`: the device's channels, and one
//! channel's parameters and objects, as a table and as paste-ready TOML.
//! Files only, no bus.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP: &str = "M-0004_A-20DE-22-C7D8-O000A";

const LOCK: &str = r#"version = 1

[[device]]
address = "1.1.47"
product = "230021SU"
application = "M-0004_A-20DE-22-C7D8-O000A"
mask = "07B0"
channels = [
  { key = "a-1", id = "MD-3_M-18_MI-1_CH-25", number = 1, text = "Jalousie 1", base = 2915 },
]
objects = [
  { number = 138, key = "in-betrieb", text = "Allgemein", function = "In Betrieb", dpt = "1.002", flags = "CRT" },
  { number = 144, key = "langzeitbetrieb", channel = "a-1", text = "Jalousie 1", function = "Langzeitbetrieb", dpt = "1.008", flags = "CWU" },
  { number = 162, key = "status-position", channel = "a-1", dpt = "5.001", flags = "CRT" },
]
parameters = [
  { key = "regenalarm", ref = "P-19_R-38", param = "P-19" },
  { key = "betriebsart", channel = "a-1", ref = "MD-3_M-18_MI-1_P-14_R-14", param = "MD-3_P-14" },
  { key = "fahrzeit", channel = "a-1", ref = "MD-3_M-18_MI-1_P-15_R-15", param = "MD-3_P-15" },
]
"#;

const DEVICE: &str = r#"address = "1.1.47"
name = "Jalousieaktor Kind 2"
product = "230021SU"

[links]
in-betrieb.send = "4/1/2"

[channel.a-1]
name = "Fenster Süd"
betriebsart = "2"
langzeitbetrieb.listen = ["0/1/3"]
"#;

const PRODUCT: &str = r#"identity:
  id: M-0004_A-20DE-22-C7D8-O000A
parameters:
  - id: M-0004_A-20DE-22-C7D8-O000A_MD-3_P-14
    text: Betriebsart
    type: !enum
      values:
        - { value: 1, text: Rollladen }
        - { value: 2, text: Jalousie }
    default: "1"
  - id: M-0004_A-20DE-22-C7D8-O000A_MD-3_P-15
    text: Fahrzeit
    type: !int
      min: 1
      max: 600
    default: "60"
  - id: M-0004_A-20DE-22-C7D8-O000A_P-19
    text: Regenalarm
    type: !enum
      values:
        - { value: 0, text: Nein }
        - { value: 1, text: Ja }
    default: "0"
"#;

/// A model directory with the device, its lock entry and its product model.
fn model_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-device-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join("models"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )?;
    std::fs::write(dir.join("bussard.lock"), LOCK)?;
    std::fs::write(dir.join("devices/1.1.47.toml"), DEVICE)?;
    std::fs::write(dir.join("models").join(format!("{APP}.yaml")), PRODUCT)?;
    Ok(dir)
}

fn bussard(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

#[test]
fn test_device_lists_channels_and_details_one_as_a_table() -> TestResult {
    let dir = model_dir("table")?;
    let d = dir.to_str().ok_or("path")?;
    let out = bussard(&["device", "1.1.47", "--dir", d])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout
            .starts_with("1.1.47 Jalousieaktor Kind 2  (230021SU, M-0004_A-20DE-22-C7D8-O000A)\n"),
        "{stdout}"
    );
    assert!(stdout.contains("a-1"), "{stdout}");
    assert!(stdout.contains("Jalousie 1"), "{stdout}");
    assert!(stdout.contains("Fenster Süd"), "{stdout}");

    let out = bussard(&["device", "1.1.47", "a-1", "--dir", d])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("channel a-1 (Jalousie 1), named \"Fenster Süd\""),
        "{stdout}"
    );
    let betriebsart = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("betriebsart"))
        .ok_or("no betriebsart row")?;
    assert!(betriebsart.contains("Jalousie"), "{betriebsart}");
    assert!(betriebsart.contains("set"), "{betriebsart}");
    assert!(
        betriebsart.contains("Rollladen | Jalousie"),
        "{betriebsart}"
    );
    let fahrzeit = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("fahrzeit"))
        .ok_or("no fahrzeit row")?;
    assert!(
        fahrzeit.contains("60") && fahrzeit.contains("default"),
        "{fahrzeit}"
    );
    assert!(stdout.contains("listens on 0/1/3"), "{stdout}");

    // An unknown channel names the ones there are.
    let out = bussard(&["device", "1.1.47", "b-9", "--dir", d])?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("its channels are: a-1, device"));
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_device_toml_is_paste_ready() -> TestResult {
    let dir = model_dir("toml")?;
    let d = dir.to_str().ok_or("path")?;
    let out = bussard(&["device", "1.1.47", "a-1", "--toml", "--dir", d])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("[channel.a-1]   # Jalousie 1\nname = \"Fenster Süd\"\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("betriebsart = \"Jalousie\"   # Betriebsart: Rollladen | Jalousie\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("# fahrzeit = \"60\"   # Fahrzeit: 1..600\n"),
        "{stdout}"
    );
    assert!(stdout.contains("# status-position.send = \"\""), "{stdout}");

    // Without product data it says so and still lists what the lock has.
    std::fs::remove_dir_all(dir.join("models"))?;
    let out = bussard(&["device", "1.1.47", "a-1", "--toml", "--dir", d])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("# note: no product data"), "{stdout}");
    assert!(stdout.contains("betriebsart = \"2\""), "{stdout}");
    assert!(stdout.contains("# fahrzeit = \"\""), "{stdout}");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
