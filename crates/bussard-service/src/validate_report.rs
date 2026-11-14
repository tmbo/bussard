//! The validation of the project in one shape (issue #904) and one rule set
//! (issue #1112): `bussard validate` and `knx_validate` both call
//! [`validate_project`] and render its [`ValidateRun`], the CLI as text or
//! `--json`, the MCP server as JSON.

use std::path::Path;

use bussard_model::{Diagnostic, IndividualAddress, KeyringFacts, Model, Severity};
use serde::Serialize;

use crate::report::Report;

/// A family of rules [`validate_project`] runs. Every surface that validates
/// the project reports the families it ran (`checked`), so a surface that
/// skips one says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSet {
    /// The rules over the loaded project: links, group addresses, flags,
    /// KNX Secure invariants, `[knxnet]` tables.
    Project,
    /// The rules that need the files themselves and the lock.
    Files,
    /// Parameter values against the product data under `.bussard/`.
    Parameters,
    /// The opt-in `[lint]` rules.
    Lint,
    /// The rules against the keyring, the key store and its exports.
    Keys,
}

impl RuleSet {
    /// Every family, in the order [`validate_project`] runs them.
    pub const ALL: [RuleSet; 5] = [
        RuleSet::Project,
        RuleSet::Files,
        RuleSet::Parameters,
        RuleSet::Lint,
        RuleSet::Keys,
    ];

    /// The codes the family can report (`docs/reference/diagnostics.md`).
    pub fn codes(self) -> &'static [&'static str] {
        match self {
            RuleSet::Project => &[
                "E001", "E002", "E003", "E004", "W005", "I006", "E007", "I009", "I010", "W011",
                "E012", "E013", "E014", "I015", "E024", "E025", "E035", "E036", "W037", "W039",
                "W041", "W042", "E043", "E044", "E045", "E046", "I048", "I049",
            ],
            RuleSet::Files => &["E020", "E021", "E022", "E023", "E032", "E033"],
            RuleSet::Parameters => &["E016", "E017", "I017", "E026", "W050"],
            RuleSet::Lint => &[
                "L001", "L002", "L003", "L004", "L005", "L006", "L007", "L008",
            ],
            RuleSet::Keys => &[
                "E027", "W028", "W029", "W030", "I031", "W034", "W040", "W047",
            ],
        }
    }
}

/// The codes no validation reports: a write refuses with them (E038, a
/// secured write only tunnel clients could make).
pub const WRITE_TIME_CODES: &[&str] = &["E038"];

/// What [`validate_project`] found and which rule families it ran.
#[derive(Debug, Clone)]
pub struct ValidateRun {
    /// The findings, sorted by location and code.
    pub diagnostics: Vec<Diagnostic>,
    /// The families that ran.
    pub checked: Vec<RuleSet>,
}

/// Validates the project in `dir` (loaded as `model`): every rule family of
/// [`RuleSet::ALL`]. `keyring` is what the surface's keyring resolution
/// found (the CLI's `BUSSARD_KEYRING` or `connection.keyring`, the server's
/// `--keyring`); `None` checks the key rules without one.
///
/// The parameter rules read the product data under `.bussard/model-cache/`;
/// see `docs/reference/diagnostics.md` for every code.
pub fn validate_project(model: &Model, dir: &Path, keyring: Option<&KeyringFacts>) -> ValidateRun {
    // Project, files, parameters, lint, and the stale key-store exports
    // (W040).
    let mut diagnostics = bussard_model::validate_in_dir(model, dir);
    // The keyring rules (issue #205): decrypted at most once by the caller,
    // never prompting.
    diagnostics.extend(bussard_model::validate_keyring(model, keyring));
    // W034 (issue #297): secured group addresses only tunnel clients write.
    diagnostics.extend(crate::admission::tunnel_gap_diagnostics(model, keyring));
    // W047 (issue #391): an IP interface's [knxnet] tunnels against the
    // tunnelling addresses the key store lists for it.
    diagnostics.extend(crate::admission::knxnet_tunnel_keyring_diagnostics(
        model, keyring,
    ));
    diagnostics.sort_by(|a, b| a.location.cmp(&b.location).then(a.code.cmp(b.code)));
    ValidateRun {
        diagnostics,
        checked: RuleSet::ALL.to_vec(),
    }
}

/// Which diagnostics a report lists.
#[derive(Debug, Clone, Default)]
pub struct ValidateFilter {
    /// The least severe diagnostic listed; `None` means warnings (errors and
    /// warnings).
    pub severity: Option<Severity>,
    /// Only diagnostics about this device (`"1.1.4"`), or a line when it
    /// ends with a dot (`"1.1."`).
    pub address: Option<String>,
    /// Only diagnostics about this group address (`"3/2/0"`), or a range
    /// when it ends with a slash (`"3/"`).
    pub group: Option<String>,
}

impl ValidateFilter {
    /// Every diagnostic.
    pub fn all() -> ValidateFilter {
        ValidateFilter {
            severity: Some(Severity::Info),
            ..ValidateFilter::default()
        }
    }
}

/// Parses a severity: `error`, `warning` or `info`.
pub fn parse_severity(text: &str) -> Option<Severity> {
    match text.trim().to_ascii_lowercase().as_str() {
        "error" | "errors" => Some(Severity::Error),
        "warning" | "warnings" => Some(Severity::Warning),
        "info" | "infos" => Some(Severity::Info),
        _ => None,
    }
}

/// How severe `s` is, most severe highest.
fn rank(s: Severity) -> u8 {
    match s {
        Severity::Error => 2,
        Severity::Warning => 1,
        Severity::Info => 0,
    }
}

/// One diagnostic.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticItem {
    /// Its code.
    pub code: String,
    /// `error`, `warning` or `info`.
    pub severity: String,
    /// Its message.
    pub message: String,
    /// Where.
    pub location: String,
    /// The device it is about, when it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The parameter key it is about, when it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
}

impl DiagnosticItem {
    /// The item of `d`.
    fn of(d: &Diagnostic) -> DiagnosticItem {
        DiagnosticItem {
            code: d.code.to_string(),
            severity: d.severity.to_string(),
            message: d.message.clone(),
            location: d.location.clone(),
            device: d
                .device
                .or_else(|| device_of(&d.location))
                .map(|ia| ia.to_string()),
            parameter: parameter_of(&d.location),
        }
    }
}

/// The device a location `devices/<address>.toml...` names.
fn device_of(location: &str) -> Option<IndividualAddress> {
    let rest = location.strip_prefix("devices/")?;
    let (stem, _) = rest.split_once(".toml")?;
    stem.parse().ok()
}

/// The parameter key a location `... parameters."<key>"` names.
fn parameter_of(location: &str) -> Option<String> {
    let (_, rest) = location.split_once("parameters.\"")?;
    let (key, _) = rest.split_once('"')?;
    Some(key.to_string())
}

/// The counts per severity over the whole project.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticCounts {
    /// Errors.
    pub errors: usize,
    /// Warnings.
    pub warnings: usize,
    /// Infos.
    pub infos: usize,
    /// All.
    pub total: usize,
}

/// The validation of the project.
#[derive(Debug, Clone, Serialize)]
pub struct ValidateReport {
    /// No error.
    pub ok: bool,
    /// The diagnostics the filter selects.
    pub diagnostics: Vec<DiagnosticItem>,
    /// The counts over all of them.
    pub counts: DiagnosticCounts,
    /// How many are listed.
    pub shown: usize,
    /// What the filter left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The rule families that ran (issue #1112).
    pub checked: Vec<RuleSet>,
    /// The rule families that did not run; absent when every one did.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_checked: Vec<RuleSet>,
}

impl ValidateReport {
    /// The report of `run` (sorted by location and code) under `filter`.
    pub fn new(run: ValidateRun, filter: &ValidateFilter) -> ValidateReport {
        let ValidateRun {
            diagnostics: mut diags,
            checked,
        } = run;
        diags.sort_by(|a, b| a.location.cmp(&b.location).then(a.code.cmp(b.code)));
        let count = |s: Severity| diags.iter().filter(|d| d.severity == s).count();
        let counts = DiagnosticCounts {
            errors: count(Severity::Error),
            warnings: count(Severity::Warning),
            infos: count(Severity::Info),
            total: diags.len(),
        };
        let floor = rank(filter.severity.unwrap_or(Severity::Warning));
        let diagnostics: Vec<DiagnosticItem> = diags
            .iter()
            .filter(|d| rank(d.severity) >= floor)
            .filter(|d| {
                filter
                    .address
                    .as_deref()
                    .is_none_or(|a| d.mentions_device(a))
            })
            .filter(|d| filter.group.as_deref().is_none_or(|g| d.mentions_group(g)))
            .map(DiagnosticItem::of)
            .collect();
        let shown = diagnostics.len();
        let note = (shown < diags.len()).then(|| {
            let mut why = Vec::new();
            if floor > 0 {
                why.push("pass `severity: \"info\"` for the infos".to_string());
            }
            if filter.address.is_some() || filter.group.is_some() {
                why.push("drop `address`/`group` for the whole project".to_string());
            }
            format!(
                "{shown} of {} diagnostics shown; `counts` covers all of them; {}",
                diags.len(),
                why.join(", ")
            )
        });
        ValidateReport {
            ok: counts.errors == 0,
            diagnostics,
            counts,
            shown,
            note,
            not_checked: RuleSet::ALL
                .into_iter()
                .filter(|r| !checked.contains(r))
                .collect(),
            checked,
        }
    }
}

impl Report for ValidateReport {
    const SCHEMA: u32 = 2;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Every `"X000"` code literal in the `.rs` files under `dir`.
    fn code_literals(dir: &Path, out: &mut BTreeSet<String>) -> TestResult {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                code_literals(&path, out)?;
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            let bytes = text.as_bytes();
            for i in 0..bytes.len().saturating_sub(5) {
                let w = &bytes[i..i + 6];
                if w[0] == b'"'
                    && matches!(w[1], b'E' | b'W' | b'I' | b'L')
                    && w[2..5].iter().all(u8::is_ascii_digit)
                    && w[5] == b'"'
                {
                    out.insert(String::from_utf8_lossy(&w[1..5]).into_owned());
                }
            }
        }
        Ok(())
    }

    fn crates() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    /// Issue #1112: the rule families name every code the rules can report
    /// (the code literals of the model and service crates) and every code
    /// `docs/reference/diagnostics.md` documents, each once, so a surface
    /// that reports `checked` cannot silently miss one.
    #[test]
    fn test_rule_set_codes_cover_the_sources_and_the_docs() -> TestResult {
        let mut listed = BTreeSet::new();
        for set in RuleSet::ALL {
            for code in set.codes() {
                assert!(listed.insert(code.to_string()), "{code} listed twice");
            }
        }
        let mut emitted = BTreeSet::new();
        code_literals(&crates().join("bussard-model/src"), &mut emitted)?;
        code_literals(&crates().join("bussard-service/src"), &mut emitted)?;
        for code in RuleSet::ALL
            .iter()
            .flat_map(|s| s.codes())
            .chain(WRITE_TIME_CODES)
        {
            emitted.remove(*code);
        }
        assert!(
            emitted.is_empty(),
            "codes no rule family lists: {emitted:?}"
        );

        let docs = std::fs::read_to_string(crates().join("../docs/reference/diagnostics.md"))?;
        let documented: BTreeSet<String> = docs
            .lines()
            .filter_map(|l| l.strip_prefix("| "))
            .filter_map(|l| l.split_once(' ').map(|(c, _)| c))
            .filter(|c| {
                c.len() == 4
                    && matches!(c.as_bytes()[0], b'E' | b'W' | b'I' | b'L')
                    && c[1..].bytes().all(|b| b.is_ascii_digit())
            })
            .map(str::to_string)
            .collect();
        let mut expected = listed.clone();
        expected.extend(WRITE_TIME_CODES.iter().map(|c| c.to_string()));
        assert_eq!(documented, expected, "docs/reference/diagnostics.md");
        Ok(())
    }

    #[test]
    fn test_diagnostic_item_of_names_device_and_parameter() -> TestResult {
        let d = Diagnostic::new(
            "W050",
            Severity::Warning,
            "devices/1.1.1.toml parameters.\"chore-interval\"",
            "replaced",
        );
        let item = DiagnosticItem::of(&d);
        assert_eq!(item.device.as_deref(), Some("1.1.1"));
        assert_eq!(item.parameter.as_deref(), Some("chore-interval"));
        let g = DiagnosticItem::of(&Diagnostic::new(
            "W011",
            Severity::Warning,
            "groups.\"1/0/0\"",
            "x",
        ));
        assert_eq!((g.device, g.parameter), (None, None));
        Ok(())
    }

    #[test]
    fn test_validate_report_new_names_what_was_not_checked() {
        let run = ValidateRun {
            diagnostics: Vec::new(),
            checked: vec![RuleSet::Project],
        };
        let report = ValidateReport::new(run, &ValidateFilter::all());
        assert_eq!(report.checked, [RuleSet::Project]);
        assert_eq!(
            report.not_checked,
            [
                RuleSet::Files,
                RuleSet::Parameters,
                RuleSet::Lint,
                RuleSet::Keys
            ]
        );
    }
}
