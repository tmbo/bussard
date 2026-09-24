//! The scripted acceptance-test runner behind `bussard test` (issue #101).
//!
//! A [`TestSuite`] loaded from the model directory's `tests.yaml` is run
//! against the live bus: each test puts a stimulus on the bus (a group write, or
//! an instruction a human carries out) and then waits for the telegram that
//! proves the installation reacted. The result is a [`Report`] that is
//! deterministic apart from its start timestamp, so two runs of a healthy house
//! produce identical output and a handover protocol can be diffed.
//!
//! The runner lives here rather than in the CLI because both `bussard test` and
//! the `knx_run_tests` MCP tool drive it, and it needs exactly what this crate
//! already owns: the decoded telegram [`ring`](crate::ring) and the bus actor.
//!
//! # Safety
//!
//! The runner writes to the bus, so its caller must already have passed the
//! non-loopback write gate. A write to a group address marked `protected: true`
//! is refused unless [`RunOptions::allow_protected`] is set, which
//! `bussard test` only does when the file says `allow_protected: true` **and**
//! `--force` was given. The MCP tool never sets it.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use bussard_bus::BusHandle;
use bussard_bus::ops::{self, WriteOptions};
use bussard_model::tests_schema::{Expectation, TestCase, TestSuite};
use bussard_model::{Dpt, GroupAddress, IndividualAddress, Model, encode, parse_value};
use bussard_transport::cemi::MessageCode;
use serde_json::{Value, json};

use crate::decode::{DecodedTelegram, DestinationRef};
use crate::ring::TelegramRing;
use crate::timefmt;

/// How a single test ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The expectation arrived (or the write succeeded and nothing was
    /// expected).
    Pass,
    /// The expectation did not arrive in time, or the stimulus could not be
    /// sent.
    Fail,
    /// The test was not run: a manual step was skipped, or the operator chose
    /// to skip it.
    Skipped,
    /// The test was refused because it writes to a protected group address
    /// without both opt-ins. Refusing is not a failure.
    Refused,
}

impl Status {
    /// A short, stable lowercase tag for JSON output.
    pub fn tag(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Skipped => "skipped",
            Status::Refused => "refused",
        }
    }

    /// The four-character label the text report puts in its left column.
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skipped => "SKIP",
            Status::Refused => "REFU",
        }
    }
}

/// The result of one test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestOutcome {
    /// The test's name, as written in `tests.yaml`.
    pub name: String,
    /// How it ended.
    pub status: Status,
    /// One sentence explaining the outcome, with no timestamps in it.
    pub detail: String,
    /// The value actually seen on the expected group address, when an
    /// expectation failed and something else arrived.
    pub observed: Option<String>,
}

impl TestOutcome {
    /// This outcome as a JSON object.
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "status": self.status.tag(),
            "detail": self.detail,
            "observed": self.observed,
        })
    }
}

/// The result of a whole run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// When the run started. The only non-deterministic part of the report.
    pub started_at: SystemTime,
    /// One outcome per test that was considered, in file order.
    pub outcomes: Vec<TestOutcome>,
}

impl Report {
    /// The number of tests with the given status.
    pub fn count(&self, status: Status) -> usize {
        self.outcomes.iter().filter(|o| o.status == status).count()
    }

    /// Whether every test that ran passed (a skipped or refused test does not
    /// fail the run).
    pub fn ok(&self) -> bool {
        self.count(Status::Fail) == 0
    }

    /// The report as JSON.
    pub fn to_json(&self) -> Value {
        json!({
            "started_at": timefmt::to_rfc3339(self.started_at),
            "tests": self.outcomes.iter().map(TestOutcome::to_json).collect::<Vec<_>>(),
            "summary": {
                "total": self.outcomes.len(),
                "passed": self.count(Status::Pass),
                "failed": self.count(Status::Fail),
                "skipped": self.count(Status::Skipped),
                "refused": self.count(Status::Refused),
                "ok": self.ok(),
            },
        })
    }

    /// The report as plain text, one line per test plus a summary. Contains no
    /// timestamps, so two runs of a healthy installation produce identical
    /// output.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for outcome in &self.outcomes {
            out.push_str(&format!("{} {}\n", outcome.status.label(), outcome.name));
            if outcome.status != Status::Pass || !outcome.detail.is_empty() {
                out.push_str(&format!("     {}\n", outcome.detail));
            }
            if let Some(observed) = &outcome.observed {
                out.push_str(&format!("     observed: {observed}\n"));
            }
        }
        out.push_str(&format!(
            "\n{} test(s): {} passed, {} failed, {} skipped, {} refused\n",
            self.outcomes.len(),
            self.count(Status::Pass),
            self.count(Status::Fail),
            self.count(Status::Skipped),
            self.count(Status::Refused),
        ));
        out
    }
}

/// What to do about a `manual:` step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualDecision {
    /// The human says they have done it; start waiting for the expectation.
    Proceed,
    /// Do not run this test; the string explains why.
    Skip(String),
}

/// How the runner asks a human to carry out a `manual:` step.
///
/// `bussard test` implements this by printing the instruction and waiting for
/// Enter. The MCP tool implements it by skipping every manual step, since there
/// is nobody at the server's terminal.
pub trait ManualStep {
    /// Presents `instruction` and reports what should happen next.
    fn prompt(&mut self, instruction: &str) -> ManualDecision;
}

/// A [`ManualStep`] that skips every manual test with a fixed reason.
#[derive(Debug, Clone)]
pub struct SkipManual {
    /// The reason recorded on each skipped test.
    pub reason: String,
}

impl ManualStep for SkipManual {
    fn prompt(&mut self, _instruction: &str) -> ManualDecision {
        ManualDecision::Skip(self.reason.clone())
    }
}

/// Knobs for one run.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Run only the tests whose names appear here (case-insensitive). Empty or
    /// `None` runs the whole file.
    pub only: Option<Vec<String>>,
    /// Permit tests that write to a protected group address. `bussard test`
    /// sets this only when `tests.yaml` says `allow_protected: true` **and**
    /// `--force` was given; the MCP tool never sets it.
    pub allow_protected: bool,
}

impl RunOptions {
    /// Whether `name` is selected by the `only` filter.
    fn selects(&self, name: &str) -> bool {
        match &self.only {
            None => true,
            Some(names) if names.is_empty() => true,
            Some(names) => names
                .iter()
                .any(|n| n.trim().eq_ignore_ascii_case(name.trim())),
        }
    }
}

/// Runs a suite against the live bus and returns the report.
///
/// Every test is attempted in file order. The runner subscribes to the telegram
/// ring **before** it puts the stimulus on the bus, so a device that answers
/// instantly cannot be missed, and it ignores the gateway's own `L_Data.con`
/// echo of the write as well as anything sent from bussard's own source
/// address, so `write: 1/0/1` / `expect: 1/0/1` tests the device, not the echo.
pub async fn run_suite(
    suite: &TestSuite,
    model: &Model,
    handle: &BusHandle,
    ring: &TelegramRing,
    options: &RunOptions,
    manual: &mut (dyn ManualStep + Send),
) -> Report {
    let started_at = SystemTime::now();
    let source = ops::group_source(handle);
    let mut outcomes = Vec::new();

    for test in &suite.tests {
        if !options.selects(&test.name) {
            continue;
        }
        outcomes.push(run_one(test, model, handle, ring, options, manual, source).await);
    }

    Report {
        started_at,
        outcomes,
    }
}

/// Runs one test. Never panics: every failure becomes a [`TestOutcome`].
async fn run_one(
    test: &TestCase,
    model: &Model,
    handle: &BusHandle,
    ring: &TelegramRing,
    options: &RunOptions,
    manual: &mut (dyn ManualStep + Send),
    source: IndividualAddress,
) -> TestOutcome {
    let outcome = |status: Status, detail: String| TestOutcome {
        name: test.name.clone(),
        status,
        detail,
        observed: None,
    };

    // The protected-GA gate, ahead of everything else: a refused test never
    // reaches the bus.
    if let Some(write) = &test.write
        && let Some(group) = model.groups.groups.get(&write.ga)
        && group.protected
        && !options.allow_protected
    {
        return outcome(
            Status::Refused,
            format!(
                "writes to protected GA {} ({:?}); needs `allow_protected: true` in the \
                         test file and --force on the command line",
                write.ga, group.name
            ),
        );
    }

    // Subscribe before the stimulus so a fast answer cannot be missed.
    let mut subscription = ring.subscribe();

    // The stimulus.
    let stimulus = if let Some(instruction) = &test.manual {
        match manual.prompt(instruction) {
            ManualDecision::Proceed => format!("after the manual step {instruction:?}"),
            ManualDecision::Skip(reason) => return outcome(Status::Skipped, reason),
        }
    } else if let Some(write) = &test.write {
        let dpt = match write
            .dpt
            .or_else(|| model.groups.groups.get(&write.ga).and_then(|g| g.dpt))
        {
            Some(dpt) => dpt,
            None => {
                return outcome(
                    Status::Fail,
                    format!(
                        "GA {} has no DPT in groups.yaml and the test gives no `dpt:`, so the \
                         value cannot be encoded",
                        write.ga
                    ),
                );
            }
        };
        let typed = match parse_value(&dpt, &write.value) {
            Ok(typed) => typed,
            Err(err) => return outcome(Status::Fail, format!("bad `write.value`: {err}")),
        };
        let payload = match encode(&dpt, &typed) {
            Ok(payload) => payload,
            Err(err) => return outcome(Status::Fail, format!("bad `write.value`: {err}")),
        };
        let opts = WriteOptions {
            // The expectation below is the confirmation; do not also wait for
            // the gateway echo, which would add a second per test.
            confirm_timeout: Duration::ZERO,
        };
        match ops::write_group(handle, write.ga, &payload, dpt.is_packable(), opts).await {
            Ok(_) => format!("after writing {} = {typed} ({dpt})", write.ga),
            Err(err) => {
                return outcome(Status::Fail, format!("could not write {}: {err}", write.ga));
            }
        }
    } else {
        // `check_suite` rejects this shape at load time; treat it defensively.
        return outcome(Status::Fail, "the test has no stimulus".to_string());
    };

    // The expectation.
    let Some(expect) = &test.expect else {
        return outcome(Status::Pass, format!("no expectation; passed {stimulus}"));
    };

    let expected_payload = match expected_payload(model, expect) {
        Ok(payload) => payload,
        Err(reason) => return outcome(Status::Fail, reason),
    };

    // The last telegram seen on the expected GA that did *not* match, so a
    // timeout can report what actually arrived. A mutex (not a cell) keeps the
    // future `Send`, which the MCP tool needs.
    let seen: Mutex<Option<String>> = Mutex::new(None);
    let matched = subscription
        .wait_for_matching(expect.within, |telegram, code| {
            if code == MessageCode::LDataCon || telegram.source == source {
                // Our own write echoing back is not the device answering.
                return false;
            }
            if telegram.destination != DestinationRef::Group(expect.ga) {
                return false;
            }
            match &expected_payload {
                None => true,
                Some(want) => {
                    if &telegram.payload == want {
                        true
                    } else {
                        if let Ok(mut slot) = seen.lock() {
                            *slot = Some(describe(telegram));
                        }
                        false
                    }
                }
            }
        })
        .await;

    let window = format_duration(expect.within);
    match matched {
        Some(_) => TestOutcome {
            name: test.name.clone(),
            status: Status::Pass,
            detail: format!(
                "{} arrived {} within {window}",
                expect.ga,
                describe_expected(expect),
            ),
            observed: None,
        },
        None => TestOutcome {
            name: test.name.clone(),
            status: Status::Fail,
            detail: format!(
                "expected {} {} within {window} {stimulus}, but it did not arrive",
                expect.ga,
                describe_expected(expect),
            ),
            observed: seen.into_inner().ok().flatten(),
        },
    }
}

/// The payload an expectation's `value:` encodes to, or `None` when the
/// expectation accepts any value.
///
/// A `value:` on a GA the model does not type is accepted as a hex literal
/// (`"0x2a"` or `"2a"`), so an untyped installation can still be tested.
fn expected_payload(model: &Model, expect: &Expectation) -> Result<Option<Vec<u8>>, String> {
    let Some(text) = &expect.value else {
        return Ok(None);
    };
    match model.groups.groups.get(&expect.ga).and_then(|g| g.dpt) {
        Some(dpt) => {
            let typed = parse_value(&dpt, text)
                .map_err(|e| format!("bad `expect.value` for GA {}: {e}", expect.ga))?;
            let payload = encode(&dpt, &typed)
                .map_err(|e| format!("bad `expect.value` for GA {}: {e}", expect.ga))?;
            Ok(Some(payload))
        }
        None => parse_hex(text).map(Some).ok_or_else(|| {
            format!(
                "GA {} has no DPT in groups.yaml, so `expect.value: {text:?}` cannot be \
                 interpreted; give the GA a DPT or write the expected payload as hex",
                expect.ga
            )
        }),
    }
}

/// Parses a hex payload literal such as `"0x2a"`, `"2a"` or `"01 0F"`.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

/// Renders what an expectation is waiting for, for the report.
fn describe_expected(expect: &Expectation) -> String {
    match &expect.value {
        Some(value) => format!("= {value}"),
        None => "(any value)".to_string(),
    }
}

/// Renders an observed telegram for a failure line.
fn describe(telegram: &DecodedTelegram) -> String {
    let value = match &telegram.value {
        Some(v) => v.to_string(),
        None => hex(&telegram.payload),
    };
    format!(
        "{} = {value} (from {})",
        telegram.destination, telegram.source
    )
}

/// Renders payload bytes as lowercase hex.
fn hex(payload: &[u8]) -> String {
    payload.iter().map(|b| format!("{b:02x}")).collect()
}

/// Renders a duration the way `tests.yaml` writes it.
fn format_duration(value: Duration) -> String {
    let millis = value.as_millis();
    if millis.is_multiple_of(1000) {
        format!("{}s", millis / 1000)
    } else {
        format!("{millis}ms")
    }
}

/// The group address a test writes to, if any. Used by callers that must gate
/// on protected GAs before the runner is even started (the MCP tool).
pub fn written_ga(test: &TestCase) -> Option<GroupAddress> {
    test.write.as_ref().map(|w| w.ga)
}

/// Whether a test writes to a group address the model marks `protected: true`.
pub fn touches_protected(model: &Model, test: &TestCase) -> bool {
    written_ga(test)
        .and_then(|ga| model.groups.groups.get(&ga))
        .map(|g| g.protected)
        .unwrap_or(false)
}

/// The DPT a test's write would encode against, if it can be resolved.
pub fn write_dpt(model: &Model, test: &TestCase) -> Option<Dpt> {
    let write = test.write.as_ref()?;
    write
        .dpt
        .or_else(|| model.groups.groups.get(&write.ga).and_then(|g| g.dpt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::error::Error;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};
    use bussard_model::tests_schema::{Expectation, TestCase, WriteStep};

    type R = Result<(), Box<dyn Error>>;

    fn model() -> Result<Model, Box<dyn Error>> {
        let mut groups = BTreeMap::new();
        groups.insert(
            "1/0/10".parse()?,
            Group {
                name: "Kitchen ceiling light".to_string(),
                dpt: Some("1.001".parse()?),
                ..Default::default()
            },
        );
        groups.insert(
            "3/1/0".parse()?,
            Group {
                name: "Wind alarm".to_string(),
                dpt: Some("1.005".parse()?),
                protected: true,
                ..Default::default()
            },
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups {
                groups,
                ..Default::default()
            },
            links: Links::default(),
            devices: BTreeMap::new(),
        })
    }

    fn write_test(name: &str, ga: &str) -> Result<TestCase, Box<dyn Error>> {
        Ok(TestCase {
            name: name.to_string(),
            write: Some(WriteStep {
                ga: ga.parse()?,
                value: "on".to_string(),
                dpt: None,
            }),
            manual: None,
            expect: None,
        })
    }

    #[test]
    fn test_touches_protected_follows_the_model() -> R {
        let m = model()?;
        assert!(touches_protected(&m, &write_test("alarm", "3/1/0")?));
        assert!(!touches_protected(&m, &write_test("light", "1/0/10")?));
        Ok(())
    }

    #[test]
    fn test_expected_payload_encodes_against_the_ga_dpt() -> R {
        let m = model()?;
        let expect = Expectation {
            ga: "1/0/10".parse()?,
            value: Some("on".to_string()),
            within: Duration::from_secs(2),
        };
        assert_eq!(expected_payload(&m, &expect)?, Some(vec![1]));
        Ok(())
    }

    #[test]
    fn test_expected_payload_any_value() -> R {
        let m = model()?;
        let expect = Expectation {
            ga: "1/0/10".parse()?,
            value: None,
            within: Duration::from_secs(2),
        };
        assert_eq!(expected_payload(&m, &expect)?, None);
        Ok(())
    }

    #[test]
    fn test_expected_payload_hex_for_an_untyped_ga() -> R {
        let m = model()?;
        let expect = Expectation {
            ga: "7/7/7".parse()?,
            value: Some("0x2a".to_string()),
            within: Duration::from_secs(2),
        };
        assert_eq!(expected_payload(&m, &expect)?, Some(vec![0x2a]));

        // A non-hex value on an untyped GA is a clear file error.
        let expect = Expectation {
            ga: "7/7/7".parse()?,
            value: Some("on".to_string()),
            within: Duration::from_secs(2),
        };
        let err = expected_payload(&m, &expect).err().ok_or("must fail")?;
        assert!(err.contains("no DPT"), "got {err}");
        Ok(())
    }

    #[test]
    fn test_parse_hex_forms() {
        assert_eq!(parse_hex("0x01"), Some(vec![1]));
        assert_eq!(parse_hex("01 0f"), Some(vec![1, 15]));
        assert_eq!(parse_hex("zz"), None);
        assert_eq!(parse_hex("1"), None);
        assert_eq!(parse_hex(""), None);
    }

    #[test]
    fn test_run_options_only_filter() {
        let all = RunOptions::default();
        assert!(all.selects("anything"));
        let some = RunOptions {
            only: Some(vec!["Kitchen light".to_string()]),
            allow_protected: false,
        };
        assert!(
            some.selects("kitchen light"),
            "matching is case-insensitive"
        );
        assert!(!some.selects("Wind alarm"));
    }

    #[test]
    fn test_report_text_and_json_are_stable() -> R {
        let report = Report {
            started_at: SystemTime::UNIX_EPOCH,
            outcomes: vec![
                TestOutcome {
                    name: "a".to_string(),
                    status: Status::Pass,
                    detail: "1/0/12 arrived = on within 2s".to_string(),
                    observed: None,
                },
                TestOutcome {
                    name: "b".to_string(),
                    status: Status::Fail,
                    detail: "expected 3/1/0 = up within 5s, but it did not arrive".to_string(),
                    observed: Some("3/1/0 = Down (from 1.1.30)".to_string()),
                },
            ],
        };
        assert!(!report.ok());
        assert_eq!(report.count(Status::Pass), 1);
        let text = report.text();
        assert!(text.contains("PASS a"), "{text}");
        assert!(text.contains("FAIL b"), "{text}");
        assert!(text.contains("observed: 3/1/0 = Down"), "{text}");
        assert!(text.contains("1 passed, 1 failed"), "{text}");

        let json = report.to_json();
        assert_eq!(json["summary"]["failed"], 1);
        assert_eq!(json["summary"]["ok"], false);
        assert_eq!(json["tests"][1]["status"], "fail");
        // Two renderings of the same report are byte-identical.
        assert_eq!(report.text(), report.text());
        Ok(())
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(2)), "2s");
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
    }

    #[test]
    fn test_skip_manual_skips_every_manual_step() {
        let mut manual = SkipManual {
            reason: "no terminal".to_string(),
        };
        assert_eq!(
            manual.prompt("press the button"),
            ManualDecision::Skip("no terminal".to_string())
        );
    }
}
