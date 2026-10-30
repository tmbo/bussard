//! The offline oracle as a gate (issue #347): `scripts/campaign/95-offline-oracle.sh
//! --check` over the owner's rows files, with this build's `bussard`.
//!
//! The captures, the project export and the model are private and never
//! committed, so the rows test is env-gated like the other corpus tests
//! (`dev/testing.md`):
//!
//! ```text
//! BUSSARD_ORACLE_ROWS=captures/campaign/rows/rows-house-16.txt:captures/campaign/rows/rows-secure-s3.txt \
//! BUSSARD_ORACLE_ROOT=/path/to/checkout   # the rows' relative paths resolve here
//! BUSSARD_ORACLE_DIR=/path/to/model-copy  # optional: --dir for every rows file
//! cargo nextest run --profile corpus -p bussard-cli -E 'test(/^offline_oracle::/)'
//! ```
//!
//! Every row whose capture and product exist runs; the script fails the check
//! when a row's verdict is not its expected one (identical unless the row says
//! `expect=...`) or its coverage dropped below the recorded figure. Rows
//! without a capture are skipped. A rows file carries its own `--keyring` and
//! `--dir` as `#@` lines. Nothing touches the bus: the script runs `flash
//! --dry-run` only.
//!
//! Two tests are ungated: one runs the script's `--check` plumbing on a row
//! whose capture does not exist, so a broken script fails every CI run; the
//! other runs `--check` over the synthetic products' committed rows
//! (`captures/synthetic/rows.txt`, epic #596), a real bussard-versus-ETS
//! comparison on every CI run.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A self-cleaning temporary directory (no `tempfile` dev-dependency needed).
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bussard-offline-oracle-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(TmpDir(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The workspace root (the script resolves `knxtrace` relative to itself).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether `python3` and `bash` run here; the script needs both. The campaign
/// scripts are POSIX shell, so Windows always skips.
fn tools_available() -> bool {
    !cfg!(windows)
        && ["python3", "bash"].iter().all(|tool| {
            Command::new(tool)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
}

/// The interpreter behind `python3`, resolved once. The script starts Python
/// about fifteen times per row; through a version-manager shim (pyenv) each
/// start costs a second or more, which made a synthetic row take 18 s instead
/// of 2 s locally. `None` leaves the script's own `python3` lookup alone.
fn resolved_python() -> Option<&'static str> {
    static PYTHON: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    PYTHON
        .get_or_init(|| {
            let out = Command::new("python3")
                .args(["-c", "import sys; print(sys.executable)"])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .ok()?;
            let path = String::from_utf8(out.stdout).ok()?.trim().to_owned();
            (out.status.success() && !path.is_empty()).then_some(path)
        })
        .as_deref()
}

/// Runs the oracle script in `cwd` with `args`; returns (success, stdout +
/// stderr). No gateway is ever configured: the script only plans dry runs.
fn oracle(cwd: &Path, args: &[&str]) -> std::io::Result<(bool, String)> {
    let script = workspace_root().join("scripts/campaign/95-offline-oracle.sh");
    let mut command = Command::new("bash");
    // A `PYTHON` the caller exported wins over the resolved interpreter.
    if std::env::var_os("PYTHON").is_none()
        && let Some(python) = resolved_python()
    {
        command.env("PYTHON", python);
    }
    let out = command
        .arg(script)
        .args(args)
        .current_dir(cwd)
        .env("BUSSARD_BIN", env!("CARGO_BIN_EXE_bussard"))
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_GATEWAY")
        .stdin(Stdio::null())
        .output()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

/// The last `n` lines of `text`, for a failure message.
fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

#[test]
fn test_offline_oracle_check_skips_a_row_without_its_capture() -> TestResult {
    if !tools_available() {
        eprintln!("SKIP: python3 or bash is not available");
        return Ok(());
    }
    let tmp = TmpDir::new("skip")?;
    let model = tmp.path().join("model");
    std::fs::create_dir_all(&model)?;
    let out = tmp.path().join("out");
    let model_arg = model.to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();
    let (ok, text) = oracle(
        tmp.path(),
        &[
            "--row",
            "9.9.9|no-such-capture.pcapng|no-such.knxprod||a note|80|expect=identical",
            "--dir",
            &model_arg,
            "--out",
            &out_arg,
            "--check",
        ],
    )?;
    assert!(
        ok,
        "the check failed on a skipped row:\n{}",
        tail(&text, 20)
    );
    assert!(text.contains("check passed"), "{}", tail(&text, 20));
    let row = std::fs::read_to_string(out.join("9.9.9/row.json"))?;
    let row: serde_json::Value = serde_json::from_str(&row)?;
    assert_eq!(row["skipped"], "capture not found");
    assert_eq!(row["recorded_coverage"], 80.0);
    Ok(())
}

#[test]
fn test_offline_oracle_rows_pass_the_check() -> TestResult {
    let Some(rows) = std::env::var_os("BUSSARD_ORACLE_ROWS") else {
        eprintln!("SKIP: BUSSARD_ORACLE_ROWS is not set (dev/testing.md)");
        return Ok(());
    };
    if !tools_available() {
        eprintln!("SKIP: python3 or bash is not available");
        return Ok(());
    }
    let root = std::env::var_os("BUSSARD_ORACLE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(workspace_root);
    let model = std::env::var("BUSSARD_ORACLE_DIR").ok();
    let tmp = TmpDir::new("rows")?;
    let mut failures = Vec::new();
    for (n, file) in std::env::split_paths(&rows).enumerate() {
        let path = if file.is_absolute() {
            file.clone()
        } else {
            root.join(&file)
        };
        if !path.is_file() {
            failures.push(format!("{}: no such rows file", path.display()));
            continue;
        }
        let out = tmp.path().join(n.to_string());
        let rows_arg = path.to_string_lossy().into_owned();
        let out_arg = out.to_string_lossy().into_owned();
        let mut args = vec!["--rows", &rows_arg, "--out", &out_arg, "--check"];
        if let Some(dir) = model.as_deref() {
            args.extend(["--dir", dir]);
        }
        let (ok, text) = oracle(&root, &args)?;
        if !ok {
            failures.push(format!("{}:\n{}", path.display(), tail(&text, 40)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    Ok(())
}

/// Copies the files of `from` into `to` (one level; the synthetic model is a
/// single `bussard.toml`, and the dry run writes its caches into the copy).
fn copy_files(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let path = entry?.path();
        if path.is_file()
            && let Some(name) = path.file_name()
        {
            std::fs::copy(&path, to.join(name))?;
        }
    }
    Ok(())
}

/// How many synthetic rows run at once. One row is one script run of about
/// 8 s that mostly waits on child processes (`knxtrace`, the bussard dry run),
/// so a few workers cut the wall time without starving the other tests nextest
/// runs next to this one.
const SYNTHETIC_WORKERS: usize = 4;

/// One synthetic row's outcome: the row line, whether it passed, how long it
/// took, and the failure detail.
struct RowOutcome {
    line: String,
    ok: bool,
    secs: f64,
    detail: String,
}

/// Runs one row of the synthetic rows file with `--check` in its own model
/// copy and output directory, so rows can run side by side (the dry run writes
/// `.bussard/` into the model).
fn check_synthetic_row(
    root: &Path,
    tmp: &Path,
    n: usize,
    line: &str,
    options: &[String],
) -> Result<RowOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let started = std::time::Instant::now();
    let dir = tmp.join(n.to_string());
    let model = dir.join("model");
    copy_files(&root.join("captures/synthetic/model"), &model)?;
    let out = dir.join("out");
    let model_arg = model.to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();
    let mut args: Vec<&str> = vec!["--row", line, "--dir", &model_arg, "--out", &out_arg];
    args.extend(options.iter().map(String::as_str));
    args.push("--check");
    let (mut ok, text) = oracle(root, &args)?;
    let mut detail = String::new();
    if !ok {
        detail = tail(&text, 40);
    } else {
        // The row ran: it was not skipped for a missing capture or product.
        let mut ran = false;
        for entry in std::fs::read_dir(&out)? {
            let row = entry?.path().join("row.json");
            if row.is_file() {
                let row: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&row)?)?;
                if !row["skipped"].is_null() {
                    ok = false;
                    detail = format!("skipped: {}", row["skipped"]);
                }
                ran = true;
            }
        }
        if !ran {
            ok = false;
            detail = format!("no row.json written:\n{}", tail(&text, 20));
        }
    }
    Ok(RowOutcome {
        line: line.to_owned(),
        ok,
        secs: started.elapsed().as_secs_f64(),
        detail,
    })
}

/// The synthetic products' rows (epic #596): committed ETS captures of
/// fabricated `M-00FA` products, the product XML zipped with the stub master
/// by the script. Ungated: everything they need is committed, so every CI run
/// on a POSIX host compares bussard's dry run with what ETS wrote.
///
/// The catalogue grows to about forty rows, so the rows run one script call
/// each on [`SYNTHETIC_WORKERS`] threads, and a failure names every failing
/// row with its time. The nextest budget for this test is an override in
/// `.config/nextest.toml`.
#[test]
fn test_offline_oracle_synthetic_rows_pass_the_check() -> TestResult {
    if !tools_available() {
        eprintln!("SKIP: python3 or bash is not available");
        return Ok(());
    }
    let root = workspace_root();
    let tmp = TmpDir::new("synthetic")?;
    let rows_file = std::fs::read_to_string(root.join("captures/synthetic/rows.txt"))?;
    // `#@` options apply to every row; `--dir` is replaced by each row's copy.
    let mut options = Vec::new();
    for line in rows_file
        .lines()
        .filter_map(|l| l.trim().strip_prefix("#@"))
    {
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word == "--dir" {
                words.next();
            } else {
                options.push(word.to_owned());
            }
        }
    }
    let rows: Vec<&str> = rows_file
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(!rows.is_empty(), "captures/synthetic/rows.txt has no row");

    let started = std::time::Instant::now();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let workers = SYNTHETIC_WORKERS.min(rows.len());
    let outcomes = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let n = next.fetch_add(1, Ordering::Relaxed);
                        let Some(line) = rows.get(n) else { break };
                        done.push(
                            check_synthetic_row(&root, tmp.path(), n, line, &options)
                                .map_err(|e| format!("{line}: {e}")),
                        );
                    }
                    done
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| vec![Err("worker panicked".to_owned())])
            })
            .collect::<Vec<_>>()
    });

    let mut timings = Vec::new();
    let mut failures = Vec::new();
    for outcome in outcomes.into_iter().flatten() {
        match outcome {
            Ok(row) => {
                timings.push(format!("{:6.1} s  {}", row.secs, row.line));
                if !row.ok {
                    failures.push(format!("{} ({:.1} s):\n{}", row.line, row.secs, row.detail));
                }
            }
            Err(e) => failures.push(e),
        }
    }
    let summary = format!(
        "{} rows on {workers} workers in {:.1} s:\n{}",
        rows.len(),
        started.elapsed().as_secs_f64(),
        timings.join("\n")
    );
    eprintln!("{summary}");
    assert!(
        failures.is_empty(),
        "synthetic rows failed the check:\n{}\n\n{summary}",
        failures.join("\n\n")
    );
    Ok(())
}
