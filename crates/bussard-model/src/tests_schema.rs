//! The acceptance-test file (`tests.yaml`) in the model directory (issue #101).
//!
//! `bussard test` runs a list of scripted functional checks against the live
//! bus: write a value, expect a telegram; or instruct a human to do something,
//! then expect a telegram. The file is the handover protocol an integrator
//! leaves behind and the owner reruns later, so it lives in the model directory
//! next to `groups.yaml` and belongs in git.
//!
//! ```yaml
//! allow_protected: false
//! tests:
//!   - name: Kitchen ceiling light switches and reports
//!     write: { ga: "1/0/10", value: "on" }
//!     expect: { ga: "1/0/12", value: "on", within: 2s }
//!   - name: Wind alarm raises the blinds
//!     manual: "Trigger the wind alarm on the weather station"
//!     expect: { ga: "3/1/0", value: "up", within: 5s }
//! ```
//!
//! This module only defines and loads the shape. The runner (which owns the
//! write gate, the protected-GA rules and the bus) lives in
//! `bussard-monitor`'s `acceptance` module, and the command wrapping it is
//! `bussard test`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::address::GroupAddress;
use crate::dpt::Dpt;

/// The conventional file name of the acceptance-test file inside a model
/// directory.
pub const TESTS_FILE: &str = "tests.yaml";

/// The default expectation window when a test does not give a `within:`.
pub const DEFAULT_WITHIN: Duration = Duration::from_secs(3);

/// An error loading or validating a `tests.yaml`.
#[derive(Debug, thiserror::Error)]
pub enum TestFileError {
    /// The file could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The YAML was syntactically invalid or contained a duplicate key.
    #[error("parsing {path}: {source}")]
    Yaml {
        /// The offending file.
        path: PathBuf,
        /// The underlying parse error.
        source: serde_norway::Error,
    },
    /// The YAML parsed but did not match the schema.
    #[error("in {path} at `{yaml_path}`: {message}")]
    Schema {
        /// The offending file.
        path: PathBuf,
        /// Human-readable YAML path to the offending value.
        yaml_path: String,
        /// The error message.
        message: String,
    },
    /// The file parsed but a test is not runnable as written.
    #[error("in {path}: test {test:?} {message}")]
    Invalid {
        /// The offending file.
        path: PathBuf,
        /// The offending test's name (or its index when it has none).
        test: String,
        /// What is wrong with it.
        message: String,
    },
}

/// A whole acceptance-test file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TestSuite {
    /// Opt-in for tests that write to a group address marked `protected: true`
    /// in `groups.yaml`.
    ///
    /// This is only half the gate: `bussard test` additionally requires
    /// `--force` on the command line, and the `knx_run_tests` MCP tool refuses
    /// such a test outright whatever this flag says. A protected GA is a wind
    /// alarm or a central function; nothing automated may drive one on the
    /// strength of a file alone.
    #[serde(default)]
    pub allow_protected: bool,
    /// The tests, run in file order.
    #[serde(default)]
    pub tests: Vec<TestCase>,
}

/// One scripted acceptance test.
///
/// A test has a stimulus — either a bus `write:` or a `manual:` instruction for
/// a human — and usually an `expect:` describing the telegram that proves the
/// installation reacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    /// The test's name, used to report it and to select it with `--only`.
    pub name: String,
    /// A group-value write to perform as the stimulus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<WriteStep>,
    /// An instruction for a human instead of a write ("press the wind-alarm
    /// test button"). The runner prints it and waits for the operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual: Option<String>,
    /// The telegram that must appear for the test to pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Expectation>,
}

impl TestCase {
    /// Whether this test needs a human to do something before the expectation
    /// can arrive.
    pub fn is_manual(&self) -> bool {
        self.manual.is_some()
    }
}

/// The write half of a test: the stimulus put on the bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteStep {
    /// The group address to write.
    pub ga: GroupAddress,
    /// The value in human form (`on`, `down`, `75%`, `21.5`), encoded against
    /// the GA's DPT exactly as `bussard write` does.
    #[serde(deserialize_with = "de_scalar_string")]
    pub value: String,
    /// Override the DPT to encode as. Defaults to the GA's DPT in
    /// `groups.yaml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpt: Option<Dpt>,
}

/// The expectation half of a test: the telegram that proves the reaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// The group address the telegram must appear on.
    pub ga: GroupAddress,
    /// The value it must carry, in human form. Omitted means "any value on this
    /// GA passes".
    #[serde(
        default,
        deserialize_with = "de_optional_scalar_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<String>,
    /// How long to wait for it. Accepts `2s`, `500ms`, `1m`, or a bare number of
    /// seconds; defaults to [`DEFAULT_WITHIN`].
    #[serde(
        default = "default_within",
        deserialize_with = "de_duration",
        serialize_with = "ser_duration"
    )]
    pub within: Duration,
}

/// The default `within:` for an expectation that does not name one.
fn default_within() -> Duration {
    DEFAULT_WITHIN
}

/// Loads a `tests.yaml` from an explicit path.
///
/// Duplicate keys and unknown fields are errors, as everywhere else in the
/// model, and every test is checked for runnability before the suite is
/// returned.
pub fn load_tests(path: &Path) -> Result<TestSuite, TestFileError> {
    let text = std::fs::read_to_string(path).map_err(|source| TestFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // Stage 1: an untyped parse, which rejects duplicate keys at any depth.
    let value: serde_norway::Value =
        serde_norway::from_str(&text).map_err(|source| TestFileError::Yaml {
            path: path.to_path_buf(),
            source,
        })?;
    // Stage 2: the typed deserialize, tracking the YAML path for errors.
    let suite: TestSuite = serde_path_to_error::deserialize(value).map_err(|err| {
        let yaml_path = err.path().to_string();
        TestFileError::Schema {
            path: path.to_path_buf(),
            yaml_path: if yaml_path.is_empty() {
                ".".to_string()
            } else {
                yaml_path
            },
            message: err.into_inner().to_string(),
        }
    })?;
    check_suite(path, &suite)?;
    Ok(suite)
}

/// Loads `<dir>/tests.yaml`, returning `Ok(None)` when the file is absent.
pub fn load_tests_in_dir(dir: &Path) -> Result<Option<TestSuite>, TestFileError> {
    let path = dir.join(TESTS_FILE);
    if !path.exists() {
        return Ok(None);
    }
    load_tests(&path).map(Some)
}

/// Rejects tests that cannot be run as written.
fn check_suite(path: &Path, suite: &TestSuite) -> Result<(), TestFileError> {
    for (index, test) in suite.tests.iter().enumerate() {
        let label = if test.name.trim().is_empty() {
            format!("#{}", index + 1)
        } else {
            test.name.clone()
        };
        let invalid = |message: &str| TestFileError::Invalid {
            path: path.to_path_buf(),
            test: label.clone(),
            message: message.to_string(),
        };
        if test.name.trim().is_empty() {
            return Err(invalid(
                "has an empty `name:`; every test needs one to report it",
            ));
        }
        if test.write.is_none() && test.manual.is_none() {
            return Err(invalid(
                "has neither `write:` nor `manual:`; a test needs a stimulus",
            ));
        }
        if test.write.is_some() && test.manual.is_some() {
            return Err(invalid(
                "has both `write:` and `manual:`; use one stimulus per test",
            ));
        }
        if test.expect.is_none() && test.manual.is_some() {
            return Err(invalid(
                "is a manual test with no `expect:`, so nothing would be checked",
            ));
        }
    }
    Ok(())
}

/// Deserializes a YAML scalar (string, boolean, integer or float) as the string
/// the value parser expects.
///
/// `value: on` is already a string in YAML 1.2, but `value: true` and
/// `value: 21.5` are not, and both are natural to write. Rendering them back to
/// text keeps one code path: everything goes through
/// [`parse_value`](crate::codec::parse_value) against the GA's DPT.
fn de_scalar_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = serde_norway::Value::deserialize(deserializer)?;
    scalar_to_string(&value)
        .ok_or_else(|| de::Error::custom("expected a scalar value (a string, boolean or number)"))
}

/// The optional form of [`de_scalar_string`].
fn de_optional_scalar_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = serde_norway::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    scalar_to_string(&value)
        .map(Some)
        .ok_or_else(|| de::Error::custom("expected a scalar value (a string, boolean or number)"))
}

/// Renders a YAML scalar as text, or `None` for a sequence/mapping/null.
fn scalar_to_string(value: &serde_norway::Value) -> Option<String> {
    match value {
        serde_norway::Value::String(s) => Some(s.clone()),
        serde_norway::Value::Bool(b) => Some(b.to_string()),
        serde_norway::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Deserializes a duration written as `2s`, `500ms`, `1m`, or a bare number of
/// seconds.
fn de_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let value = serde_norway::Value::deserialize(deserializer)?;
    let text = scalar_to_string(&value)
        .ok_or_else(|| de::Error::custom("expected a duration like `2s`, `500ms` or `2`"))?;
    parse_duration(&text).map_err(de::Error::custom)
}

/// Serializes a duration back to the compact form the file uses.
fn ser_duration<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&render_duration(*value))
}

/// Renders a duration as `2s` or `500ms`.
fn render_duration(value: Duration) -> String {
    let millis = value.as_millis();
    if millis.is_multiple_of(1000) {
        format!("{}s", millis / 1000)
    } else {
        format!("{millis}ms")
    }
}

/// Parses `2s`, `500ms`, `1m`, `1.5s` or a bare number of seconds.
///
/// Returns a message naming the accepted forms, so a typo in `tests.yaml`
/// points at the fix.
pub fn parse_duration(text: &str) -> Result<Duration, DurationParseError> {
    let raw = text.trim();
    let bad = || DurationParseError {
        input: raw.to_string(),
    };
    let (digits, unit) = match raw.find(|c: char| c.is_alphabetic()) {
        Some(at) => (raw[..at].trim(), raw[at..].trim()),
        None => (raw, ""),
    };
    let amount: f64 = digits.parse().map_err(|_| bad())?;
    if !amount.is_finite() || amount < 0.0 {
        return Err(bad());
    }
    let seconds = match unit {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => amount,
        "ms" | "milli" | "millis" | "millisecond" | "milliseconds" => amount / 1000.0,
        "m" | "min" | "mins" | "minute" | "minutes" => amount * 60.0,
        _ => return Err(bad()),
    };
    Duration::try_from_secs_f64(seconds).map_err(|_| bad())
}

/// Error parsing a `within:` duration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected a duration like `2s`, `500ms` or `2` (seconds), got {input:?}")]
pub struct DurationParseError {
    /// The offending text.
    pub input: String,
}

impl fmt::Display for TestSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} test(s)", self.tests.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    type R = Result<(), Box<dyn Error>>;

    fn write_temp(name: &str, body: &str) -> Result<PathBuf, Box<dyn Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-tests-schema-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(TESTS_FILE);
        std::fs::write(&path, body)?;
        Ok(path)
    }

    #[test]
    fn test_load_tests_parses_the_issue_example() -> R {
        let path = write_temp(
            "example",
            r#"
allow_protected: true
tests:
  - name: Kitchen ceiling light switches and reports
    write: { ga: "1/0/10", value: on }
    expect: { ga: "1/0/12", value: on, within: 2s }
  - name: Wind alarm raises the blinds
    manual: "Trigger the wind alarm on the weather station"
    expect: { ga: "3/1/0", value: up, within: 5s }
"#,
        )?;
        let suite = load_tests(&path)?;
        assert!(suite.allow_protected);
        assert_eq!(suite.tests.len(), 2);

        let first = &suite.tests[0];
        let write = first.write.as_ref().ok_or("first test writes")?;
        assert_eq!(write.ga, "1/0/10".parse()?);
        assert_eq!(write.value, "on");
        let expect = first.expect.as_ref().ok_or("first test expects")?;
        assert_eq!(expect.ga, "1/0/12".parse()?);
        assert_eq!(expect.value.as_deref(), Some("on"));
        assert_eq!(expect.within, Duration::from_secs(2));

        let second = &suite.tests[1];
        assert!(second.is_manual());
        assert_eq!(
            second.expect.as_ref().ok_or("second expects")?.within,
            Duration::from_secs(5)
        );
        let _ = std::fs::remove_dir_all(path.parent().ok_or("parent")?);
        Ok(())
    }

    #[test]
    fn test_load_tests_in_dir_absent_is_none() -> R {
        let dir = std::env::temp_dir().join(format!("bussard-no-tests-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        assert!(load_tests_in_dir(&dir)?.is_none());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn test_load_tests_rejects_unknown_fields() -> R {
        let path = write_temp(
            "unknown",
            "tests:\n  - name: a\n    write: { ga: \"1/0/1\", value: on, oops: 1 }\n",
        )?;
        let err = load_tests(&path).err().ok_or("must reject")?;
        assert!(
            matches!(err, TestFileError::Schema { .. }),
            "expected a schema error, got {err}"
        );
        let _ = std::fs::remove_dir_all(path.parent().ok_or("parent")?);
        Ok(())
    }

    #[test]
    fn test_load_tests_rejects_a_test_without_a_stimulus() -> R {
        let path = write_temp(
            "no-stimulus",
            "tests:\n  - name: nothing happens\n    expect: { ga: \"1/0/1\" }\n",
        )?;
        let err = load_tests(&path).err().ok_or("must reject")?;
        assert!(err.to_string().contains("stimulus"), "got {err}");
        let _ = std::fs::remove_dir_all(path.parent().ok_or("parent")?);
        Ok(())
    }

    #[test]
    fn test_load_tests_rejects_both_stimuli() -> R {
        let path = write_temp(
            "both",
            "tests:\n  - name: two ways\n    manual: press it\n    write: { ga: \"1/0/1\", value: on }\n    expect: { ga: \"1/0/2\" }\n",
        )?;
        let err = load_tests(&path).err().ok_or("must reject")?;
        assert!(err.to_string().contains("one stimulus"), "got {err}");
        let _ = std::fs::remove_dir_all(path.parent().ok_or("parent")?);
        Ok(())
    }

    #[test]
    fn test_expectation_defaults_the_window() -> R {
        let path = write_temp(
            "default-within",
            "tests:\n  - name: a\n    write: { ga: \"1/0/1\", value: on }\n    expect: { ga: \"1/0/2\" }\n",
        )?;
        let suite = load_tests(&path)?;
        let expect = suite.tests[0].expect.as_ref().ok_or("expect")?;
        assert_eq!(expect.within, DEFAULT_WITHIN);
        assert!(expect.value.is_none(), "any value passes");
        let _ = std::fs::remove_dir_all(path.parent().ok_or("parent")?);
        Ok(())
    }

    #[test]
    fn test_scalar_values_accept_booleans_and_numbers() -> R {
        let path = write_temp(
            "scalars",
            "tests:\n  - name: a\n    write: { ga: \"1/0/1\", value: true }\n    expect: { ga: \"1/0/2\", value: 21.5 }\n",
        )?;
        let suite = load_tests(&path)?;
        assert_eq!(suite.tests[0].write.as_ref().ok_or("write")?.value, "true");
        assert_eq!(
            suite.tests[0]
                .expect
                .as_ref()
                .ok_or("expect")?
                .value
                .as_deref(),
            Some("21.5")
        );
        let _ = std::fs::remove_dir_all(path.parent().ok_or("parent")?);
        Ok(())
    }

    #[test]
    fn test_parse_duration_forms() -> R {
        assert_eq!(parse_duration("2s")?, Duration::from_secs(2));
        assert_eq!(parse_duration("500ms")?, Duration::from_millis(500));
        assert_eq!(parse_duration("1m")?, Duration::from_secs(60));
        assert_eq!(parse_duration("3")?, Duration::from_secs(3));
        assert_eq!(parse_duration(" 1.5 s ")?, Duration::from_millis(1500));
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("2 fortnights").is_err());
        Ok(())
    }

    #[test]
    fn test_render_duration_roundtrips() -> R {
        for text in ["2s", "500ms", "60s"] {
            assert_eq!(render_duration(parse_duration(text)?), text);
        }
        Ok(())
    }
}
