//! Issue #1112: `bussard validate` and `knx_validate` run one rule set
//! (`bussard_service::validate_report::validate_project`). Each test builds
//! the project of `syn-assign-rewrite` (#1054) with a parameter finding,
//! validates it through the CLI (`validate --json`) and through a passive
//! `bussard mcp` on a closed loopback port, and compares the findings: the
//! same codes, severities, locations and counts, and the same `checked`
//! rule families, every one of them.

use std::path::Path;
use std::process::{Command, Stdio};

use bussard_testkit::TestResult;
use serde_json::{Value, json};

use crate::flash_dry_run::{TmpDir, assign_rewrite_project};
use crate::mcp_stdio_client::McpServer;

/// Every rule family `validate_project` runs, by its JSON name.
const ALL_RULE_SETS: [&str; 5] = ["project", "files", "parameters", "lint", "keys"];

/// `(code, severity, location, device, parameter)` of each diagnostic.
fn findings(report: &Value) -> Vec<(String, String, String, String, String)> {
    let field = |d: &Value, k: &str| d[k].as_str().unwrap_or_default().to_string();
    let mut out: Vec<_> = report["diagnostics"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|d| {
                    (
                        field(d, "code"),
                        field(d, "severity"),
                        field(d, "location"),
                        field(d, "device"),
                        field(d, "parameter"),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// `bussard validate --json` over `dir`.
fn cli_validate(dir: &Path) -> TestResult<Value> {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["validate", "--json", "--dir"])
        .arg(dir)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .stdin(Stdio::null())
        .output()?;
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// `knx_validate` with every severity, from a passive server on `dir`.
fn mcp_validate(dir: &Path) -> TestResult<Value> {
    let mut server =
        McpServer::start_without_keyring(dir, 9, &[], &["--passive", "--no-model-edits"])?;
    server.call("knx_validate", json!({"severity": "info"}))
}

/// Validates the `syn-assign-rewrite` project with `edit` applied to its
/// device file through both surfaces, asserts they agree, and returns the
/// codes they report.
fn both(tag: &str, edit: impl Fn(&str) -> String) -> TestResult<Vec<String>> {
    let tmp = TmpDir::new(tag)?;
    let dir = assign_rewrite_project(tmp.path())?;
    let device = dir.join("devices/1.1.1.toml");
    std::fs::write(&device, edit(&std::fs::read_to_string(&device)?))?;

    let cli = cli_validate(&dir)?;
    let mcp = mcp_validate(&dir)?;
    assert_eq!(findings(&cli), findings(&mcp), "CLI:\n{cli}\nMCP:\n{mcp}");
    assert_eq!(cli["counts"], mcp["counts"], "CLI:\n{cli}\nMCP:\n{mcp}");
    for report in [&cli, &mcp] {
        assert_eq!(report["checked"], json!(ALL_RULE_SETS), "{report}");
        assert!(report.get("not_checked").is_none(), "{report}");
    }
    Ok(findings(&cli).into_iter().map(|f| f.0).collect())
}

/// W050: "Chore interval" is 1000 in the project; the `<Assign>` of mode
/// `automatic` replaces it with the delay, so both surfaces warn once.
#[test]
fn test_validate_parity_assign_rewrite_w050() -> TestResult {
    let codes = both("parity-w050", str::to_string)?;
    assert_eq!(
        codes.iter().filter(|c| *c == "W050").count(),
        1,
        "{codes:?}"
    );
    Ok(())
}

/// E016: a parameter key the product does not have.
#[test]
fn test_validate_parity_unknown_parameter_e016() -> TestResult {
    let codes = both("parity-e016", |text| {
        format!("{}\n\"bogus@P-99_R-99\" = 1\n", text.trim_end())
    })?;
    assert_eq!(
        codes.iter().filter(|c| *c == "E016").count(),
        1,
        "{codes:?}"
    );
    Ok(())
}

/// E017: a value out of the parameter's range.
#[test]
fn test_validate_parity_out_of_range_e017() -> TestResult {
    let codes = both("parity-e017", |text| {
        text.replace("nap-length = 7", "nap-length = 99999999")
    })?;
    assert_eq!(
        codes.iter().filter(|c| *c == "E017").count(),
        1,
        "{codes:?}"
    );
    Ok(())
}
