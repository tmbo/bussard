//! `bussard groups reserve`: the conventional block for one room and trade,
//! appended to `groups.toml` under the project's scheme. Files only, no bus.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn model_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-groups-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:3671\"\n",
    )?;
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
fn test_groups_reserve_appends_the_block_and_prints_the_addresses() -> TestResult {
    let dir = model_dir("reserve")?;
    let d = dir.to_str().ok_or("path")?;
    let out = bussard(&["groups", "reserve", "EG Küche", "light", "--dir", d])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("reserved 2 group address(es) for EG Küche"),
        "{stdout}"
    );
    assert!(stdout.contains("1/1/0"), "{stdout}");
    assert!(stdout.contains("EG Küche Light Switch"), "{stdout}");
    // The scheme is now recorded in bussard.toml.
    let config = std::fs::read_to_string(dir.join("bussard.toml"))?;
    assert!(
        config.contains("scheme = \"floor-trade-block\""),
        "{config}"
    );

    // A second room on the same floor and trade takes the next block.
    let out = bussard(&[
        "groups", "reserve", "EG Bad", "light", "blind", "--dir", d, "--json",
    ])?;
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(json["added"][0]["address"], "1/1/5", "{json}");
    assert_eq!(json["room"], "EG Bad", "{json}");

    // Re-running adds nothing and renumbers nothing.
    let out = bussard(&["groups", "reserve", "EG Küche", "light", "--dir", d])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing added"), "{stdout}");

    // A scheme that contradicts bussard.toml is refused.
    let out = bussard(&[
        "groups",
        "reserve",
        "OG Kind",
        "light",
        "--scheme",
        "function-floor",
        "--dir",
        d,
    ])?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("floor-trade-block scheme"));

    // A label without a room is refused with the fix.
    let out = bussard(&["groups", "reserve", "Küche", "light", "--dir", d])?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not name a floor and a room"));
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
