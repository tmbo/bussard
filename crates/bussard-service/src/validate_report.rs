//! The validation of the project in one shape (issue #904): `bussard
//! validate --json` and `knx_validate`.

use bussard_model::{Diagnostic, Severity};
use serde::Serialize;

use crate::report::Report;

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
}

impl ValidateReport {
    /// The report of `diags` (sorted by location and code) under `filter`.
    pub fn new(mut diags: Vec<Diagnostic>, filter: &ValidateFilter) -> ValidateReport {
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
            .map(|d| DiagnosticItem {
                code: d.code.to_string(),
                severity: d.severity.to_string(),
                message: d.message.clone(),
                location: d.location.clone(),
            })
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
        }
    }
}

impl Report for ValidateReport {
    const SCHEMA: u32 = 2;
}
