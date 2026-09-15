//! CLI tests for the product-data pointer index surface of `import-product`:
//! `--list`, the not-found error for an unknown order number, and the
//! no-arguments error. No network: `--order-number` for a real entry would hit
//! the vendor, so these cover only the offline branches.

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn list_shows_index_entries() {
    let (ok, stdout, stderr) = run(&["import-product", "--list"]);
    assert!(ok, "--list should succeed; stderr={stderr}");
    // The seeded MDT entries and their order numbers appear.
    assert!(stdout.contains("MDT"), "stdout={stdout}");
    assert!(stdout.contains("AKK-0216.03"), "stdout={stdout}");
    assert!(stdout.contains("mdt.de"), "stdout={stdout}");
    // Shows the pointer index framing, not a payload.
    assert!(stdout.contains("pointer index"), "stdout={stdout}");
}

#[test]
fn order_number_not_in_index_errors() {
    let (ok, _stdout, stderr) = run(&["import-product", "--order-number", "NOPE-9999"]);
    assert!(!ok, "unknown order number should fail");
    assert!(
        stderr.contains("no product-data entry") || stderr.contains("NOPE-9999"),
        "stderr={stderr}"
    );
}

#[test]
fn no_arguments_errors() {
    let (ok, _stdout, stderr) = run(&["import-product"]);
    assert!(!ok, "no arguments should fail");
    assert!(stderr.contains("nothing to import"), "stderr={stderr}");
}
