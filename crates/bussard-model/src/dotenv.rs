//! `BUSSARD_*` variables from a `.env` file (issue #251).
//!
//! bussard reads one `.env` file so the keyring and project passwords and the
//! other `BUSSARD_*` settings do not have to be exported before every command.
//! The CLI finds the file ([`find`]), reads it ([`read`]) and installs its
//! values once at start-up ([`install`]); every reader of a `BUSSARD_*`
//! variable then asks [`var`] / [`var_os`] instead of `std::env`.
//!
//! The rules:
//!
//! * Lookup order: `<model dir>/.env`, then `.env` in the directory that holds
//!   the model directory, then `.env` in the working directory. The first file
//!   found is used; files are never merged.
//! * A variable present in the process environment wins over the file, even
//!   when it is empty.
//! * Only `BUSSARD_*` keys are applied. [`NEVER_FROM_FILE`] lists the keys a
//!   file may not set at all: `BUSSARD_ALLOW_REAL_GATEWAY` stays flag-only or
//!   explicitly exported, so a `.env` can never open the write gate.
//! * Syntax: `KEY=value`, an optional `export ` prefix, `#` comment lines,
//!   blank lines, single or double quotes around the value. An unquoted value
//!   ends at ` #` (a trailing comment). No interpolation, no escapes.
//!
//! * [`DISABLE_ENV`] (`BUSSARD_NO_DOTENV=1`, process environment only) skips
//!   the file.
//! * [`store`] writes one key into a `.env` (the project password a chat
//!   user typed into bussard's password form, issue #818); [`store_target`]
//!   picks the file the lookup above finds, so the next command reads it.
//!   [`remember`] makes the stored value visible to this process too.
//!
//! No function here prints or logs a value.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// The file name looked up in each candidate directory.
pub const FILE_NAME: &str = ".env";

/// The only key prefix a `.env` may set.
pub const PREFIX: &str = "BUSSARD_";

/// `BUSSARD_*` keys a `.env` may never set. `BUSSARD_ALLOW_REAL_GATEWAY`
/// opts a write in to a real gateway; that stays an explicit act (the flag or
/// an exported variable), so the file is ignored for it.
pub const NEVER_FROM_FILE: &[&str] = &["BUSSARD_ALLOW_REAL_GATEWAY"];

/// Set to `1` in the process environment, this skips the `.env` entirely
/// (hermetic scripts and test harnesses). A `.env` cannot set it.
pub const DISABLE_ENV: &str = "BUSSARD_NO_DOTENV";

/// Whether [`DISABLE_ENV`] is `1` in the process environment.
#[must_use]
pub fn disabled() -> bool {
    std::env::var_os(DISABLE_ENV).is_some_and(|value| value == "1")
}

/// The values installed from the `.env` file, set once per process.
static FILE_VALUES: OnceLock<BTreeMap<String, String>> = OnceLock::new();

/// Values this process stored in its `.env` after start-up ([`remember`]).
/// They win over [`FILE_VALUES`], which still holds the file as it was read.
static STORED_VALUES: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

/// Parses `.env` text into its `BUSSARD_*` assignments, in file order.
///
/// Keys without the [`PREFIX`], lines without `=`, and keys that are not
/// plain identifiers are skipped. CRLF line ends are accepted.
#[must_use]
pub fn parse(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let valid = key.starts_with(PREFIX)
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            valid.then(|| (key.to_string(), unquote(value.trim()).to_string()))
        })
        .collect()
}

/// The value without its quotes; an unquoted value without its trailing
/// ` #` comment.
fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(rest) = value.strip_prefix(quote) {
            return rest.find(quote).map_or(rest, |end| &rest[..end]);
        }
    }
    value
        .find(" #")
        .or_else(|| value.find("\t#"))
        .map_or(value, |end| value[..end].trim_end())
}

/// The candidate `.env` files for `model_dir` and the working directory
/// `cwd`, in lookup order: the model directory, its parent, then `cwd`.
/// Duplicates (a model directory that is `cwd`) are listed once.
#[must_use]
pub fn candidates(model_dir: &Path, cwd: &Path) -> Vec<PathBuf> {
    let parent = match model_dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        // A relative single-component dir (`knx`) lives in `cwd`.
        _ => cwd.to_path_buf(),
    };
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in [model_dir, parent.as_path(), cwd] {
        let file = dir.join(FILE_NAME);
        let same = |seen: &PathBuf| {
            seen == &file || (std::path::absolute(seen).ok() == std::path::absolute(&file).ok())
        };
        if !out.iter().any(same) {
            out.push(file);
        }
    }
    out
}

/// The `.env` file to use: the first of [`candidates`] that is a file.
#[must_use]
pub fn find(model_dir: &Path, cwd: &Path) -> Option<PathBuf> {
    candidates(model_dir, cwd)
        .into_iter()
        .find(|file| file.is_file())
}

/// Reads and parses the `.env` file at `path`.
///
/// # Errors
///
/// The I/O error of reading the file (it names no value).
pub fn read(path: &Path) -> std::io::Result<Vec<(String, String)>> {
    Ok(parse(&std::fs::read_to_string(path)?))
}

/// What [`install`] did with a file's assignments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Installed {
    /// Keys taken from the file (not set in the process environment).
    pub applied: Vec<String>,
    /// Keys the process environment already sets; the file lost.
    pub shadowed: Vec<String>,
    /// Keys in [`NEVER_FROM_FILE`]; ignored.
    pub refused: Vec<String>,
}

/// Installs `pairs` as the process's `.env` values. A later duplicate key in
/// the file wins over an earlier one, as in a shell. Only the first call per
/// process takes effect; a later call changes nothing and returns an empty
/// report.
pub fn install(pairs: Vec<(String, String)>) -> Installed {
    let mut report = Installed::default();
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in pairs {
        if NEVER_FROM_FILE.contains(&key.as_str()) {
            report.refused.push(key);
        } else if std::env::var_os(&key).is_some() {
            report.shadowed.push(key);
        } else {
            values.insert(key, value);
        }
    }
    report.applied = values.keys().cloned().collect();
    for list in [&mut report.shadowed, &mut report.refused] {
        list.sort();
        list.dedup();
    }
    if FILE_VALUES.set(values).is_err() {
        return Installed::default();
    }
    report
}

/// `std::env::var` with the installed `.env` values as the fallback: the
/// process environment wins (even an empty value), else the file.
///
/// # Errors
///
/// [`std::env::VarError::NotPresent`] when neither sets `name`,
/// [`std::env::VarError::NotUnicode`] for a non-UTF-8 process value.
pub fn var(name: &str) -> Result<String, std::env::VarError> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => stored_value(name)
            .or_else(|| file_value(name).map(str::to_string))
            .ok_or(std::env::VarError::NotPresent),
        other => other,
    }
}

/// A millisecond knob: [`var`] read as a whole number of milliseconds
/// (surrounding whitespace ignored). `None` when unset or not a number.
///
/// The `BUSSARD_*_MS` test hooks (discovery, management and probe timeouts,
/// reconnect backoff, flash waits) all read through this.
pub fn duration_ms(name: &str) -> Option<std::time::Duration> {
    var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_millis)
}

/// `std::env::var_os` with the installed `.env` values as the fallback.
#[must_use]
pub fn var_os(name: &str) -> Option<OsString> {
    std::env::var_os(name)
        .or_else(|| stored_value(name).map(OsString::from))
        .or_else(|| file_value(name).map(OsString::from))
}

/// Makes `value` the `.env` value of `name` for the rest of this process,
/// after [`store`] wrote it to the file. The process environment still wins.
pub fn remember(name: &str, value: &str) {
    let mut stored = match STORED_VALUES.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    stored.insert(name.to_string(), value.to_string());
}

/// The value [`remember`] recorded for `name`.
fn stored_value(name: &str) -> Option<String> {
    let stored = match STORED_VALUES.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    stored.get(name).cloned()
}

/// The `.env` file a value for the model directory `model_dir` is stored
/// in: the file [`find`] picks, else a new `.env` next to the model
/// directory (in its parent), the second place the lookup looks.
#[must_use]
pub fn store_target(model_dir: &Path, cwd: &Path) -> PathBuf {
    find(model_dir, cwd).unwrap_or_else(|| {
        candidates(model_dir, cwd)
            .into_iter()
            .nth(1)
            .unwrap_or_else(|| model_dir.join(FILE_NAME))
    })
}

/// `value` as it is written after `KEY=` so that [`parse`] reads it back
/// unchanged: bare when it holds only plain characters, else in single
/// quotes, else in double quotes. `None` when no form reads back (a line
/// break, or both quote characters).
fn encode_value(value: &str) -> Option<String> {
    if value.contains(['\n', '\r']) {
        return None;
    }
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.,:/@%+=".contains(c));
    if plain {
        Some(value.to_string())
    } else if !value.contains('\'') {
        Some(format!("'{value}'"))
    } else if !value.contains('"') {
        Some(format!("\"{value}\""))
    } else {
        None
    }
}

/// Sets `key` to `value` in the `.env` file at `path`: the first line that
/// assigns `key` is replaced, later ones are dropped (a later duplicate would
/// win), every other line is kept as it is. A missing file is created with
/// mode 0600 on Unix; an existing file keeps its mode. The file is replaced
/// atomically.
///
/// # Errors
///
/// `key` is not a `BUSSARD_*` key, `value` cannot be written so [`parse`]
/// reads it back (a line break, or both quote characters), or the file
/// cannot be read or written. No error text holds the value.
pub fn store(path: &Path, key: &str, value: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let invalid =
        |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, what.to_string());
    let valid_key =
        key.starts_with(PREFIX) && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid_key {
        return Err(invalid("not a BUSSARD_* key"));
    }
    let encoded = encode_value(value).ok_or_else(|| {
        invalid("the value holds a line break or both quote characters, which a .env cannot hold")
    })?;
    // Write through a symlink to the file it names.
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let (old, permissions) = match std::fs::read_to_string(&path) {
        Ok(text) => (text, std::fs::metadata(&path).ok().map(|m| m.permissions())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (String::new(), None),
        Err(err) => return Err(err),
    };
    let line = format!("{key}={encoded}");
    let mut replaced = false;
    let mut lines: Vec<&str> = Vec::new();
    for existing in old.lines() {
        if parse(existing).first().is_some_and(|(k, _)| k == key) {
            if !replaced {
                lines.push(&line);
                replaced = true;
            }
        } else {
            lines.push(existing);
        }
    }
    if !replaced {
        lines.push(&line);
    }
    let mut text = lines.join("\n");
    text.push('\n');

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".env.bussard-{}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&tmp, permissions)?;
        }
        std::fs::rename(&tmp, &path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// The installed `.env` value of `name`, ignoring the process environment.
fn file_value(name: &str) -> Option<&'static str> {
    FILE_VALUES.get()?.get(name).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn pairs(text: &str) -> Vec<(String, String)> {
        parse(text)
    }

    fn kv(key: &str, value: &str) -> (String, String) {
        (key.to_string(), value.to_string())
    }

    /// A fresh, empty scratch directory for one test.
    fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
        let dir =
            std::env::temp_dir().join(format!("bussard-dotenv-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::canonicalize(&dir)
    }

    #[test]
    fn test_parse_plain_and_export_prefix() {
        assert_eq!(
            pairs("BUSSARD_A=1\nexport BUSSARD_B=two\n"),
            vec![kv("BUSSARD_A", "1"), kv("BUSSARD_B", "two")]
        );
    }

    #[test]
    fn test_parse_quotes_keep_inner_text() {
        assert_eq!(
            pairs("BUSSARD_A=\"a b # c\"\nBUSSARD_B='x=y'\nBUSSARD_C=\"\"\n"),
            vec![
                kv("BUSSARD_A", "a b # c"),
                kv("BUSSARD_B", "x=y"),
                kv("BUSSARD_C", "")
            ]
        );
    }

    #[test]
    fn test_parse_quoted_value_with_trailing_comment() {
        assert_eq!(
            pairs("BUSSARD_A=\"v\" # note\n"),
            vec![kv("BUSSARD_A", "v")]
        );
    }

    #[test]
    fn test_parse_comments_and_blank_lines() {
        assert_eq!(
            pairs("# header\n\n   \n  # BUSSARD_X=1\nBUSSARD_A=v # note\nBUSSARD_B=p#ss\n"),
            vec![kv("BUSSARD_A", "v"), kv("BUSSARD_B", "p#ss")]
        );
    }

    #[test]
    fn test_parse_ignores_non_bussard_keys() {
        assert_eq!(
            pairs("HA_TOKEN=secret\nPATH=/x\nBUSSARDX=1\nBUSSARD_OK=1\nBUSSARD_BAD KEY=1\n"),
            vec![kv("BUSSARD_OK", "1")]
        );
    }

    #[test]
    fn test_parse_crlf_line_ends() {
        assert_eq!(
            pairs("BUSSARD_A=1\r\nBUSSARD_B=\"q\"\r\n"),
            vec![kv("BUSSARD_A", "1"), kv("BUSSARD_B", "q")]
        );
    }

    #[test]
    fn test_parse_no_interpolation() {
        assert_eq!(
            pairs("BUSSARD_A=$HOME/${USER}\n"),
            vec![kv("BUSSARD_A", "$HOME/${USER}")]
        );
    }

    #[test]
    fn test_parse_spaces_around_equals_and_missing_equals() {
        assert_eq!(
            pairs("BUSSARD_A = spaced \nBUSSARD_B\n"),
            vec![kv("BUSSARD_A", "spaced")]
        );
    }

    #[test]
    fn test_candidates_order_model_parent_cwd() {
        let got = candidates(Path::new("/r/knx"), Path::new("/w"));
        assert_eq!(
            got,
            vec![
                PathBuf::from("/r/knx/.env"),
                PathBuf::from("/r/.env"),
                PathBuf::from("/w/.env")
            ]
        );
    }

    #[test]
    fn test_candidates_relative_default_dir_dedups_cwd() {
        let got = candidates(Path::new("knx"), Path::new("."));
        assert_eq!(
            got,
            vec![PathBuf::from("knx/.env"), PathBuf::from("./.env")]
        );
    }

    #[test]
    fn test_find_prefers_model_dir() -> TestResult {
        let root = scratch("model-first")?;
        let model = root.join("knx");
        let cwd = root.join("work");
        std::fs::create_dir_all(&model)?;
        std::fs::create_dir_all(&cwd)?;
        for dir in [&model, &root, &cwd] {
            std::fs::write(dir.join(FILE_NAME), "BUSSARD_A=1\n")?;
        }
        assert_eq!(find(&model, &cwd), Some(model.join(FILE_NAME)));
        std::fs::remove_file(model.join(FILE_NAME))?;
        assert_eq!(find(&model, &cwd), Some(root.join(FILE_NAME)));
        std::fs::remove_file(root.join(FILE_NAME))?;
        assert_eq!(find(&model, &cwd), Some(cwd.join(FILE_NAME)));
        std::fs::remove_file(cwd.join(FILE_NAME))?;
        assert_eq!(find(&model, &cwd), None);
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn test_find_ignores_a_directory_named_env() -> TestResult {
        let root = scratch("env-dir")?;
        let model = root.join("knx");
        std::fs::create_dir_all(model.join(FILE_NAME))?;
        std::fs::write(root.join(FILE_NAME), "BUSSARD_A=1\n")?;
        assert_eq!(find(&model, &root), Some(root.join(FILE_NAME)));
        std::fs::remove_dir_all(&root)?;
        Ok(())
    }

    /// The one test that installs: the install is once per process, and
    /// nextest runs each test in its own process.
    #[test]
    fn test_install_precedence_and_refusal() -> TestResult {
        // A key no test process exports.
        let exported = std::env::vars()
            .map(|(key, _)| key)
            .find(|key| key.starts_with(PREFIX));
        let mut input = vec![
            kv("BUSSARD_DOTENV_TEST_ONLY", "from-file"),
            kv("BUSSARD_ALLOW_REAL_GATEWAY", "1"),
        ];
        if let Some(key) = &exported {
            input.push(kv(key, "from-file"));
        }
        let report = install(input);
        assert_eq!(report.applied, vec!["BUSSARD_DOTENV_TEST_ONLY".to_string()]);
        assert_eq!(
            report.refused,
            vec!["BUSSARD_ALLOW_REAL_GATEWAY".to_string()]
        );
        assert_eq!(var("BUSSARD_DOTENV_TEST_ONLY")?, "from-file");
        assert_eq!(
            var_os("BUSSARD_DOTENV_TEST_ONLY"),
            Some(OsString::from("from-file"))
        );
        // The refused key never reaches the fallback.
        assert_eq!(file_value("BUSSARD_ALLOW_REAL_GATEWAY"), None);
        if let Some(key) = &exported {
            assert_eq!(report.shadowed, vec![key.clone()]);
            assert_eq!(var_os(key), std::env::var_os(key));
        }
        // A second install changes nothing.
        let again = install(vec![kv("BUSSARD_DOTENV_TEST_ONLY", "other")]);
        assert_eq!(again, Installed::default());
        assert_eq!(var("BUSSARD_DOTENV_TEST_ONLY")?, "from-file");
        Ok(())
    }

    #[test]
    fn test_store_creates_file_with_mode_0600() -> TestResult {
        let dir = scratch("store-create")?;
        let file = dir.join(FILE_NAME);
        store(&file, "BUSSARD_PROJECT_PASSWORD", "p w#'x")?;
        assert_eq!(read(&file)?, vec![kv("BUSSARD_PROJECT_PASSWORD", "p w#'x")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{mode:o}");
        }
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_store_replaces_the_key_and_keeps_other_lines() -> TestResult {
        let dir = scratch("store-replace")?;
        let file = dir.join(FILE_NAME);
        std::fs::write(
            &file,
            "# mine\nexport BUSSARD_PROJECT_PASSWORD=old\nBUSSARD_KEYRING_PASSWORD=k\n\nOTHER=1\nBUSSARD_PROJECT_PASSWORD=older",
        )?;
        store(&file, "BUSSARD_PROJECT_PASSWORD", "new-pw")?;
        assert_eq!(
            std::fs::read_to_string(&file)?,
            "# mine\nBUSSARD_PROJECT_PASSWORD=new-pw\nBUSSARD_KEYRING_PASSWORD=k\n\nOTHER=1\n"
        );
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_store_refuses_values_a_env_cannot_hold() -> TestResult {
        let dir = scratch("store-refuse")?;
        let file = dir.join(FILE_NAME);
        for value in ["a\nb", "it's \"x\""] {
            let err = store(&file, "BUSSARD_PROJECT_PASSWORD", value)
                .err()
                .ok_or("refused")?;
            assert!(!err.to_string().contains(value), "{err}");
        }
        assert!(store(&file, "PATH", "x").is_err());
        assert!(!file.exists());
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_encode_value_round_trips_through_parse() -> TestResult {
        for value in [
            "plain-1.2",
            "with space",
            "a#b",
            " lead",
            "it's",
            "x\"y",
            "",
            "$HOME",
        ] {
            let encoded = encode_value(value).ok_or("encodable")?;
            assert_eq!(
                parse(&format!("BUSSARD_X={encoded}")),
                vec![kv("BUSSARD_X", value)],
                "{value:?} as {encoded}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_store_target_prefers_the_found_file_else_the_parent() -> TestResult {
        let root = scratch("store-target")?;
        let model = root.join("knx");
        let cwd = root.join("elsewhere");
        std::fs::create_dir_all(&model)?;
        std::fs::create_dir_all(&cwd)?;
        assert_eq!(store_target(&model, &cwd), root.join(FILE_NAME));
        std::fs::write(cwd.join(FILE_NAME), "BUSSARD_A=1\n")?;
        assert_eq!(store_target(&model, &cwd), cwd.join(FILE_NAME));
        std::fs::write(model.join(FILE_NAME), "BUSSARD_A=1\n")?;
        assert_eq!(store_target(&model, &cwd), model.join(FILE_NAME));
        std::fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn test_remember_wins_over_the_file() -> TestResult {
        remember("BUSSARD_DOTENV_REMEMBER_TEST", "stored");
        assert_eq!(var("BUSSARD_DOTENV_REMEMBER_TEST")?, "stored");
        assert_eq!(
            var_os("BUSSARD_DOTENV_REMEMBER_TEST"),
            Some(OsString::from("stored"))
        );
        Ok(())
    }
}
