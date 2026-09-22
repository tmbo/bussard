//! Golden tests for the plain-language change renderer (issue #112).
//!
//! Each case under `tests/fixtures/change/<case>/` holds an `old/` and a `new/`
//! model directory plus the `expected.txt` rendering. The test loads both
//! models, runs [`bussard_model::change::describe`] and compares
//! [`render_text`](bussard_model::change::render_text) against the fixture, so a
//! wording change has to be made deliberately.
//!
//! Every [`ChangeKind`] the schema allows has at least one case; the last test
//! asserts that, so a new kind cannot ship without a golden.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use bussard_model::Model;
use bussard_model::change::{ChangeKind, ChangeSet, describe, render_text};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The fixture root.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/change")
}

/// Every case directory, sorted by name.
fn cases() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(fixtures())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    Ok(out)
}

/// Describes one case's `old` → `new` change.
fn describe_case(case: &Path) -> Result<ChangeSet, Box<dyn std::error::Error>> {
    let old = Model::load(&case.join("old"))?;
    let new = Model::load(&case.join("new"))?;
    Ok(describe(&old, &new))
}

#[test]
fn test_describe_matches_every_golden_rendering() -> TestResult {
    let cases = cases()?;
    assert!(
        !cases.is_empty(),
        "no fixtures found under {:?}",
        fixtures()
    );
    for case in cases {
        let name = case.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let expected = std::fs::read_to_string(case.join("expected.txt"))?;
        let actual = render_text(&describe_case(&case)?);
        assert_eq!(
            actual, expected,
            "case {name}: rendering changed\n--- actual ---\n{actual}--- expected ---\n{expected}"
        );
    }
    Ok(())
}

#[test]
fn test_describe_is_deterministic_and_never_empty_sentenced() -> TestResult {
    for case in cases()? {
        let name = case.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let first = describe_case(&case)?;
        let second = describe_case(&case)?;
        assert_eq!(first, second, "case {name}: describe is not deterministic");
        assert!(!first.is_empty(), "case {name}: produced no changes at all");
        for change in &first.changes {
            assert!(
                !change.sentence.trim().is_empty(),
                "case {name}: a {:?} change rendered an empty sentence",
                change.kind
            );
            assert!(
                change.sentence.ends_with('.'),
                "case {name}: {:?} is not a sentence",
                change.sentence
            );
        }
    }
    Ok(())
}

#[test]
fn test_a_model_compared_with_itself_has_no_changes() -> TestResult {
    for case in cases()? {
        let model = Model::load(&case.join("new"))?;
        assert!(describe(&model, &model).is_empty());
    }
    Ok(())
}

#[test]
fn test_protected_changes_are_flagged_and_sorted_first() -> TestResult {
    for case in cases()? {
        let set = describe_case(&case)?;
        for change in &set.changes {
            assert_eq!(
                change.touches_protected,
                change
                    .sentence
                    .ends_with("This group address is protected."),
                "the protected flag and the sentence must agree: {:?}",
                change.sentence
            );
        }
        // Once a non-protected sentence has been printed, no protected one may
        // follow it.
        let text = render_text(&set);
        let mut seen_plain = false;
        for line in text.lines() {
            let protected = line.ends_with("This group address is protected.");
            assert!(
                !(protected && seen_plain),
                "protected sentences must come first:\n{text}"
            );
            seen_plain |= !protected;
        }
    }
    Ok(())
}

#[test]
fn test_the_change_set_serializes_to_json_with_its_structure() -> TestResult {
    let case = fixtures().join("link-added");
    let set = describe_case(&case)?;
    let json = serde_json::to_value(&set)?;
    let first = &json["changes"][0];
    assert_eq!(first["kind"], "link_added");
    assert_eq!(first["device"], "1.1.5");
    assert_eq!(first["group"], "0/0/4");
    assert_eq!(first["object"], 1);
    assert_eq!(first["role"], "send");
    assert_eq!(first["touches_protected"], false);
    assert!(
        first["sentence"]
            .as_str()
            .is_some_and(|s| s.contains("Porch light"))
    );
    Ok(())
}

#[test]
fn test_every_change_kind_has_at_least_one_golden() -> TestResult {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for case in cases()? {
        for change in describe_case(&case)?.changes {
            seen.insert(format!("{:?}", change.kind));
        }
    }
    let required = [
        ChangeKind::GroupAdded,
        ChangeKind::GroupRemoved,
        ChangeKind::GroupRenamed,
        ChangeKind::GroupDptChanged,
        ChangeKind::GroupDescriptionChanged,
        ChangeKind::GroupProtectionChanged,
        ChangeKind::LinkAdded,
        ChangeKind::LinkRemoved,
        ChangeKind::DeviceAdded,
        ChangeKind::DeviceRemoved,
        ChangeKind::DeviceRenamed,
        ChangeKind::DeviceMoved,
        ChangeKind::DeviceProductChanged,
        ChangeKind::ParameterChanged,
        ChangeKind::ChannelRenamed,
        ChangeKind::ConnectionChanged,
    ];
    for kind in required {
        assert!(
            seen.contains(&format!("{kind:?}")),
            "no golden fixture covers {kind:?}"
        );
    }
    Ok(())
}
