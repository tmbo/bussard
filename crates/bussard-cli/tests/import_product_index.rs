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

    // The index carries the multi-vendor flashability corpus: several
    // manufacturers and a range of device types, not just the two seed
    // switch-actuator entries. These names come straight from the corpus that
    // tests-support/product-corpus sweeps; keep them in step with
    // data/product-index.json.
    for vendor in ["MDT", "Zennio", "Lingg & Janke", "Theben", "Elsner"] {
        assert!(
            stdout.contains(vendor),
            "expected {vendor} in --list; stdout={stdout}"
        );
    }
    // A representative order number from a non-MDT vendor resolves too.
    assert!(stdout.contains("ZVI-F1"), "stdout={stdout}");

    // The header reports the entry count; the corpus is well past 20 entries.
    let count = parse_entry_count(&stdout).expect("--list should report an entry count");
    assert!(
        count >= 20,
        "product index should hold at least 20 entries, got {count}; stdout={stdout}"
    );
}

/// Pulls the entry count out of the `--list` header line
/// (`Product-data pointer index (N entries):`).
fn parse_entry_count(stdout: &str) -> Option<usize> {
    let line = stdout.lines().find(|l| l.contains("pointer index ("))?;
    let open = line.find('(')?;
    let rest = &line[open + 1..];
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
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
