//! knx-sim's independence from bussard, asserted mechanically.
//!
//! The whole value of this simulator is that it is a *second, independent*
//! implementation: two implementations meeting on the wire is the cross-check,
//! and a misconception shared through a common dependency would defeat it. The
//! isolation is currently structural — knx-sim is its own Cargo workspace and
//! the root manifest excludes it — which means nothing stops someone adding
//! `bussard-transport = { path = "../crates/bussard-transport" }` and quietly
//! turning the cross-check into a tautology.
//!
//! These tests read the manifest and the lockfile as text (no TOML dependency
//! for a job a few lines of `std` do) and fail if that ever happens.

/// The crate's own manifest, embedded at compile time.
const MANIFEST: &str = include_str!("../Cargo.toml");
/// The crate's lockfile, embedded at compile time. It is committed precisely so
/// this assertion — and `cargo deny` — have something to read.
const LOCKFILE: &str = include_str!("../Cargo.lock");

/// The lines of every dependency table in the manifest, paired with the table
/// header they appeared under.
///
/// Section-aware on purpose: `[lib]` and `[[bin]]` legitimately carry
/// `path = "src/lib.rs"`, so a naive search for `path =` over the whole file
/// would be a false positive.
fn dependency_lines(manifest: &str) -> Vec<(String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(['[', ']']).to_string();
            continue;
        }
        if line.is_empty() {
            continue;
        }
        // `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`,
        // `[target.'cfg(...)'.dependencies]` and the `[dependencies.foo]` form.
        let is_dep_table = section
            .rsplit('.')
            .next()
            .is_some_and(|last| last.ends_with("dependencies"))
            || section.contains("dependencies.");
        if is_dep_table {
            out.push((section.clone(), line.to_string()));
        }
    }
    out
}

#[test]
fn test_dependency_lines_flags_a_violating_manifest() {
    // The scanner is only worth having if it actually catches the regression it
    // guards against — and if it does not mistake `[lib] path` for a dependency.
    let bad = concat!(
        "[package]\nname = \"knx-sim\"\n\n",
        "[lib]\npath = \"src/lib.rs\"\n\n",
        "[dependencies]\n",
        "bussard-transport = { path = \"../crates/bussard-transport\" }\n",
        "serde = \"1\"\n",
    );
    let deps = dependency_lines(bad);
    assert_eq!(deps.len(), 2, "only the [dependencies] lines are scanned");
    assert!(
        deps.iter().any(|(_, line)| line.contains("path =")),
        "a path dependency is detected"
    );
    assert!(
        deps.iter()
            .any(|(_, line)| line.starts_with("bussard-transport")),
        "a bussard dependency is detected"
    );
}

#[test]
fn test_manifest_has_no_path_or_git_dependency() {
    // A `path` dependency could only point back into the bussard workspace, and
    // a `git` dependency would break both the "crates.io only" rule and the
    // cleanly-extractable claim in README.md.
    let deps = dependency_lines(MANIFEST);
    assert!(
        !deps.is_empty(),
        "no dependency table found in the manifest"
    );
    for (section, line) in &deps {
        assert!(
            !line.contains("path ="),
            "[{section}] declares a path dependency, which would couple knx-sim \
             to another checkout: {line}"
        );
        assert!(
            !line.contains("git ="),
            "[{section}] declares a git dependency; knx-sim is crates.io-only: {line}"
        );
        assert!(
            !line.contains("registry ="),
            "[{section}] declares an alternative registry; knx-sim is crates.io-only: {line}"
        );
    }
}

#[test]
fn test_manifest_has_no_bussard_dependency() {
    for (section, line) in dependency_lines(MANIFEST) {
        let name = line
            .split(['=', '.'])
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"');
        assert!(
            !name.starts_with("bussard"),
            "[{section}] depends on {name}: knx-sim must share no code with the \
             tool it cross-checks"
        );
    }
}

#[test]
fn test_lockfile_resolves_only_crates_io() {
    // The manifest is the declaration; the lockfile is what actually gets built.
    // A transitive git or local dependency shows up here even if the manifest
    // looks clean.
    for line in LOCKFILE.lines().map(str::trim) {
        if let Some(source) = line.strip_prefix("source = ") {
            assert_eq!(
                source.trim_matches('"'),
                "registry+https://github.com/rust-lang/crates.io-index",
                "the lockfile resolves a non-crates.io source: {line}"
            );
        }
        if let Some(name) = line.strip_prefix("name = ") {
            let name = name.trim_matches('"');
            assert!(
                name == "knx-sim" || !name.starts_with("bussard"),
                "the lockfile contains a bussard package: {name}"
            );
        }
    }
}

#[test]
fn test_manifest_is_its_own_workspace_and_unpublished() {
    // The empty `[workspace]` table is what actually detaches knx-sim from the
    // bussard workspace at the parent path; the root `exclude` alone would not.
    assert!(
        MANIFEST.contains("[workspace]"),
        "knx-sim must declare its own [workspace] to stay standalone"
    );
    assert!(
        MANIFEST.contains("publish = false"),
        "knx-sim is a development tool and must not be publishable"
    );
}
