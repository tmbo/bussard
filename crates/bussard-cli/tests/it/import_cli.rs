//! `bussard import` and `init` end to end on the tiny fabricated project
//! ([`super::tiny_project`]): the model is validated after the write, the
//! keyring next to the project is recorded or imported. No bus and no
//! network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The tiny project, written into `dir`.
fn fixture(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("project.knxproj");
    super::tiny_project::write(&path)?;
    Ok(path)
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
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_KEYRING_PASSWORD")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}

#[test]
fn test_import_into_a_fresh_dir_writes_the_gitignore_with_env() -> TestResult {
    let tmp = tmp("gitignore")?;
    let dir = tmp.join("knx");
    let project = fixture(&tmp)?;
    let out = bussard(
        &[
            "import",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let ignore = std::fs::read_to_string(dir.join(".gitignore"))?;
    assert_eq!(
        ignore.lines().filter(|l| *l == ".env").count(),
        1,
        "{ignore}"
    );
    assert!(ignore.lines().any(|l| l == ".bussard/"), "{ignore}");
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// The first run is one command: `init <project>` writes `bussard.toml`, then
/// imports the project into the fresh directory (not a re-import).
#[test]
fn test_init_with_a_project_file_imports_it() -> TestResult {
    let tmp = tmp("init")?;
    let dir = tmp.join("knx");
    let project = fixture(&tmp)?;
    let out = bussard(
        &[
            "init",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--routing",
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Importing"), "{stdout}");
    assert!(
        stdout.contains("imported 2 group addresses, 1 devices"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("re-import"),
        "a fresh import, not a merge: {stdout}"
    );
    assert!(stdout.contains("validation: 0 error(s)"), "{stdout}");
    assert!(stdout.contains("bussard device <address>"), "{stdout}");
    let config = std::fs::read_to_string(dir.join("bussard.toml"))?;
    assert!(config.contains("transport = \"routing\""), "{config}");
    assert!(dir.join("devices/1.1.1.toml").is_file());
    assert!(dir.join("groups.toml").is_file());
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// Issue #205: a `.knxkeys` exported next to the project is recorded as
/// `connection.keyring` (relative to the model directory), `init` prints the
/// password reminder, and `validate` resolves the recorded path. The keyring
/// is the committed synthetic one; nothing decrypts it here.
#[test]
fn test_init_records_the_keyring_next_to_the_project() -> TestResult {
    let tmp = tmp("init-keyring")?;
    let project = fixture(&tmp)?;
    let synthetic = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../knx-sim/examples/secure/synthetic.knxkeys");
    std::fs::copy(&synthetic, tmp.join("Site.knxkeys"))?;
    let dir = tmp.join("knx");
    let out = bussard(
        &[
            "init",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--routing",
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Found the ETS keyring"), "{stdout}");
    assert!(stdout.contains("BUSSARD_KEYRING_PASSWORD"), "{stdout}");
    assert!(stdout.contains("bussard keys import"), "{stdout}");
    // Without the password no store can be written.
    assert!(!dir.join("bussard.keys").exists());
    // The recorded path resolves to the keyring (compared as paths, not
    // strings, so the check holds on Windows too).
    let config = bussard_model::load_config(&dir)?;
    let recorded = config
        .connection
        .keyring_path(&dir)
        .ok_or("init recorded no connection.keyring")?;
    assert_eq!(
        std::fs::canonicalize(&recorded)?,
        std::fs::canonicalize(tmp.join("Site.knxkeys"))?,
        "recorded {}",
        recorded.display()
    );
    let text = std::fs::read_to_string(dir.join("bussard.toml"))?;
    assert!(!text.contains('\\'), "forward slashes only: {text}");

    // `validate` resolves it: present, and without the password one info line.
    let out = bussard(
        &[
            "validate",
            "--dir",
            dir.to_str().ok_or("path")?,
            "--format",
            "json",
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("E027"), "{stdout}");

    // A keyring that went away is an error naming the file.
    std::fs::remove_file(tmp.join("Site.knxkeys"))?;
    let out = bussard(&["validate", "--dir", dir.to_str().ok_or("path")?], &[])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "{stdout}");
    assert!(stdout.contains("error[E027]"), "{stdout}");
    assert!(stdout.contains("Site.knxkeys"), "{stdout}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// Issue #241 item 2: with the password set, `init` (through its import)
/// merges the `.knxkeys` next to the project into `bussard.keys` and records
/// no `connection.keyring`; a re-import with a newer export merges again.
#[test]
fn test_init_and_import_create_the_key_store_from_a_neighbouring_keyring() -> TestResult {
    let tmp = tmp("init-keystore")?;
    let project = fixture(&tmp)?;
    let synthetic = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../knx-sim/examples/secure/synthetic.knxkeys");
    std::fs::copy(&synthetic, tmp.join("Site.knxkeys"))?;
    let dir = tmp.join("knx");
    let password = [("BUSSARD_KEYRING_PASSWORD", "synthetic-keyring-pw")];
    let out = bussard(
        &[
            "init",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--routing",
        ],
        &password,
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Imported the ETS keyring"), "{stdout}");
    assert!(stdout.contains("created"), "{stdout}");
    assert_eq!(
        stdout.matches("BUSSARD_KEYRING_PASSWORD").count(),
        1,
        "one password reminder: {stdout}"
    );
    assert!(dir.join("bussard.keys").exists());
    let config = bussard_model::load_config(&dir)?;
    assert!(
        config.connection.keyring_path(&dir).is_none(),
        "no connection.keyring with a store"
    );
    let gitignore = std::fs::read_to_string(dir.join(".gitignore"))?;
    assert!(gitignore.contains("*.knxkeys"), "{gitignore}");

    // A plain re-import finds the same export: nothing changes.
    let out = bussard(
        &[
            "import",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
        ],
        &password,
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("already up to date"), "{stdout}");
    assert!(!dir.join("bussard.keys.bak").exists());

    // A wrong password warns and leaves the import (and the store) alone.
    let out = bussard(
        &[
            "import",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
        ],
        &[("BUSSARD_KEYRING_PASSWORD", "wrong")],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("was not imported"), "{stderr}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// Issue #923: an export without the device's application program (what an
/// ETS export without product data would be) is refused before anything is
/// written, so an import never reaches a product download.
#[test]
fn test_import_project_without_product_data_is_refused_before_writing() -> TestResult {
    let tmp = tmp("no-product-data")?;
    let full = fixture(&tmp)?;
    let stripped = tmp.join("stripped.knxproj");
    let app_entry = format!("M-9999/{}.xml", super::tiny_project::APP_ID);
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&full)?)?;
    let mut zw = zip::ZipWriter::new(std::fs::File::create(&stripped)?);
    for i in 0..archive.len() {
        let entry = archive.by_index_raw(i)?;
        if entry.name()? != app_entry.as_str() {
            zw.raw_copy_file(entry)?;
        }
    }
    zw.finish()?;
    let dir = tmp.join("knx");
    let out = bussard(
        &[
            "import",
            stripped.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains(&format!(
            "application program `{}` referenced by device 1.1.1 was not found in the archive",
            super::tiny_project::APP_ID
        )),
        "{stderr}"
    );
    assert!(!dir.join("devices").exists(), "nothing is written");
    assert!(!stdout.contains("product data missing"), "{stdout}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}
