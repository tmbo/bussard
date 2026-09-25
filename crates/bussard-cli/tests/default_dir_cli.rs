//! Every command defaults to the current directory: discovery falls back to
//! `.`, `init` and `import` write into `.` and ask before writing into a
//! non-empty one, and the "no model" error names the current directory. Each
//! case runs in its own temp directory with no terminal on stdin. No bus, no
//! network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The small xknxproject JSON fixture shared with the import tests.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../bussard-project/tests/fixtures/tiny.xknxproject.json")
}

/// A unique, empty, canonical temp directory.
fn scratch(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-default-dir-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(std::fs::canonicalize(&dir)?)
}

/// Runs `bussard args` in `cwd`, without a terminal and without the
/// variables that could point it elsewhere.
fn bussard(cwd: &Path, args: &[&str]) -> TestResult<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.current_dir(cwd)
        .args(args)
        .env("BUSSARD_NO_DOTENV", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in [
        "BUSSARD_DIR",
        "BUSSARD_GATEWAY",
        "BUSSARD_KEYRING",
        "BUSSARD_KEYRING_PASSWORD",
        "BUSSARD_PRODUCT_INDEX",
    ] {
        cmd.env_remove(key);
    }
    Ok(cmd.output()?)
}

fn import_args(extra: &[&'static str]) -> TestResult<Vec<String>> {
    let fixture = fixture();
    let mut args = vec![
        "import".to_string(),
        "--from-json".to_string(),
        fixture.to_str().ok_or("fixture path")?.to_string(),
        "--no-download".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    Ok(args)
}

fn run_import(cwd: &Path, extra: &[&'static str]) -> TestResult<Output> {
    let args = import_args(extra)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    bussard(cwd, &args)
}

#[test]
fn test_import_into_non_empty_cwd_without_terminal_refuses() -> TestResult {
    let dir = scratch("refuse")?;
    std::fs::write(dir.join("notes.txt"), "mine")?;
    let out = run_import(&dir, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    let expected = format!(
        "refusing to import into the non-empty current directory {} (1 entry) without a \
         terminal to confirm on; pass --yes to confirm non-interactively",
        dir.display()
    );
    assert!(stderr.contains(&expected), "{stderr}");
    assert!(!dir.join("groups.toml").exists(), "nothing written");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_import_into_non_empty_cwd_with_yes_writes_here() -> TestResult {
    let dir = scratch("yes")?;
    std::fs::write(dir.join("notes.txt"), "mine")?;
    let out = run_import(&dir, &["--yes"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(dir.join("groups.toml").is_file());
    assert_eq!(std::fs::read_to_string(dir.join("notes.txt"))?, "mine");

    // A re-import into the model it wrote asks nothing.
    let out = run_import(&dir, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_import_into_empty_cwd_asks_nothing() -> TestResult {
    let dir = scratch("empty")?;
    std::fs::write(dir.join(".env"), "")?;
    std::fs::create_dir_all(dir.join(".git"))?;
    let out = run_import(&dir, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(dir.join("groups.toml").is_file());
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_import_names_the_nested_model() -> TestResult {
    let dir = scratch("nested")?;
    std::fs::create_dir_all(dir.join("knx"))?;
    std::fs::write(dir.join("knx").join("bussard.toml"), "")?;
    let out = run_import(&dir, &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("(1 entry, a model exists in knx/)"),
        "{stderr}"
    );
    assert!(!dir.join("groups.toml").exists());
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_init_into_non_empty_cwd_without_terminal_refuses() -> TestResult {
    let dir = scratch("init")?;
    std::fs::write(dir.join("README.md"), "repo")?;
    let out = bussard(&dir, &["init", "--routing"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "refusing to initialise a model in the non-empty current directory {} (1 entry)",
            dir.display()
        )),
        "{stderr}"
    );
    assert!(!dir.join("bussard.toml").exists());
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_no_model_error_names_the_current_directory() -> TestResult {
    let dir = scratch("no-model")?;
    let out = bussard(&dir, &["backup"])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "no model in the current directory {}",
            dir.display()
        )) && stderr
            .contains("run `bussard init` or `bussard import <export>` there, or pass --dir"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
