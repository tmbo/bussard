//! `bussard import` end to end on the small xknxproject JSON fixture: the
//! group addresses a device uses are declared, the model is validated after
//! the write, and the summary names the devices written without product data.
//! No bus and no network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The fixture shared with `bussard-project`'s import tests.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../bussard-project/tests/fixtures/tiny.xknxproject.json")
}

fn tmp(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-import-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn bussard(args: &[&str], envs: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.args(args)
        .env_remove("BUSSARD_PRODUCT_INDEX")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}

/// The fixture with the status object also listening on `1/0/9`, which the
/// project does not define.
fn fixture_with_undefined_ga(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(fixture())?;
    let text = text.replace(
        "\"group_address_links\": [\"1/0/2\"]",
        "\"group_address_links\": [\"1/0/2\", \"1/0/9\"]",
    );
    let path = dir.join("project.json");
    std::fs::write(&path, text)?;
    Ok(path)
}

#[test]
fn test_import_declares_a_group_address_the_project_uses_but_does_not_define() -> TestResult {
    let tmp = tmp("declare")?;
    let project = fixture_with_undefined_ga(&tmp)?;
    let dir = tmp.join("knx");
    let out = bussard(
        &[
            "import",
            "--from-json",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("added 1/0/9 \"Test Switch Actuator object 1\""),
        "{stdout}"
    );
    let groups = std::fs::read_to_string(dir.join("groups.toml"))?;
    assert!(groups.contains("\"1/0/9\""), "{groups}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}
