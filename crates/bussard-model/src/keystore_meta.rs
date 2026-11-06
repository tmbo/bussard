//! When the key store last changed and when each keyring export was written
//! (issue #348), and the stale-export warning W040 that reads it.
//!
//! A keyring consumer outside bussard (Home Assistant, ETS, a visualisation)
//! holds the keys of the export it loaded. Once `bussard.keys` changes after
//! that export (a group address switched plain or secured, a newer ETS keyring
//! imported), the consumer encrypts with a key the devices no longer use, or
//! cannot decrypt a newly secured address. Nothing in the key store itself
//! says so, and its encrypted XML has no room for bussard's bookkeeping, so the
//! times live next to it in `bussard.keys.meta.toml`, git-tracked with the
//! store:
//!
//! ```toml
//! changed = "2026-10-24T18:02:11Z"
//!
//! [[export]]
//! path = "/home/me/ha/knx.knxkeys"
//! written = "2026-10-20T09:15:00Z"
//! ```
//!
//! `changed` is set when a write changes an existing store (creating the store
//! from an ETS keyring is no change: that keyring is what the consumers
//! already have). Each `bussard keys export` records its file. The file holds
//! paths and UTC times only, never a key.
//!
//! * **W040**: a recorded export that still exists predates `changed`; or
//!   `[home_assistant]` is configured and no export is newer than `changed`.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::loader::Model;
use crate::validate::{Diagnostic, Severity};

/// The metadata file's name, next to `bussard.keys`.
pub const KEYSTORE_META_FILE: &str = "bussard.keys.meta.toml";

/// The header comment of the metadata file.
const HEADER: &str = "# When the key store bussard.keys last changed and when each keyring export \
was written (issue #348).\n# Written by `bussard keys` and every command that changes the key \
store; read by `bussard validate` (W040). No key material.\n\n";

/// The key store's bookkeeping: its last change and the exports written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyStoreMeta {
    /// When a write last changed an existing key store, as an RFC 3339 UTC
    /// time (`2026-10-24T18:02:11Z`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<String>,
    /// The keyring exports `bussard keys export` wrote, one per path.
    #[serde(default, rename = "export", skip_serializing_if = "Vec::is_empty")]
    pub exports: Vec<ExportRecord>,
}

/// One keyring export bussard wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRecord {
    /// The export file: absolute, or relative to the model directory.
    pub path: String,
    /// When it was written, as an RFC 3339 UTC time.
    pub written: String,
}

/// Why the metadata file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreMetaError {
    /// Reading or writing the file failed.
    #[error("{path}: {source}")]
    Io {
        /// The metadata file.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The file is not valid metadata.
    #[error("{path}: {source}")]
    Parse {
        /// The metadata file.
        path: PathBuf,
        /// The TOML error.
        source: toml::de::Error,
    },
    /// The metadata did not serialize.
    #[error("serializing {path}: {source}")]
    Serialize {
        /// The metadata file.
        path: PathBuf,
        /// The TOML error.
        source: toml::ser::Error,
    },
}

/// The current time as the metadata records it.
pub fn now() -> String {
    crate::history::rfc3339(SystemTime::now())
}

impl KeyStoreMeta {
    /// The metadata file of the model in `dir`.
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(KEYSTORE_META_FILE)
    }

    /// Reads the metadata of the model in `dir`; empty when there is none.
    ///
    /// # Errors
    ///
    /// The file exists but does not read or parse.
    pub fn load(dir: &Path) -> Result<Self, KeyStoreMetaError> {
        let path = Self::path(dir);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(KeyStoreMetaError::Io { path, source }),
        };
        toml::from_str(&text).map_err(|source| KeyStoreMetaError::Parse { path, source })
    }

    /// Writes the metadata of the model in `dir`.
    ///
    /// # Errors
    ///
    /// The file does not serialize or write.
    pub fn save(&self, dir: &Path) -> Result<(), KeyStoreMetaError> {
        let path = Self::path(dir);
        let body = toml::to_string(self).map_err(|source| KeyStoreMetaError::Serialize {
            path: path.clone(),
            source,
        })?;
        std::fs::write(&path, format!("{HEADER}{body}"))
            .map_err(|source| KeyStoreMetaError::Io { path, source })
    }

    /// Records that the key store in `dir` changed now.
    ///
    /// # Errors
    ///
    /// The metadata does not read or write.
    pub fn record_change(dir: &Path) -> Result<(), KeyStoreMetaError> {
        let mut meta = Self::load(dir)?;
        meta.changed = Some(now());
        meta.save(dir)
    }

    /// Records that `file` was exported from the key store in `dir` now,
    /// replacing an earlier record of the same file. A file inside `dir` is
    /// recorded relative to it, so the record survives a moved checkout.
    ///
    /// # Errors
    ///
    /// The metadata does not read or write.
    pub fn record_export(dir: &Path, file: &Path) -> Result<(), KeyStoreMetaError> {
        let mut meta = Self::load(dir)?;
        let path = record_path(dir, file);
        meta.exports.retain(|e| e.path != path);
        meta.exports.push(ExportRecord {
            path,
            written: now(),
        });
        meta.exports.sort_by(|a, b| a.path.cmp(&b.path));
        meta.save(dir)
    }
}

/// The path an export is recorded under: relative to `dir` when inside it,
/// else absolute.
fn record_path(dir: &Path, file: &Path) -> String {
    let file = std::fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
    let base = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    match file.strip_prefix(&base) {
        Ok(rel) => rel.display().to_string(),
        Err(_) => file.display().to_string(),
    }
}

/// The recorded export path resolved against the model directory.
fn resolve(dir: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        dir.join(p)
    }
}

/// W040 for the model in `dir` (see the module docs), for a caller that
/// validates without [`crate::validate_in_dir`] (the MCP server's
/// `knx_validate`).
pub fn stale_export_diagnostics(model: &Model, dir: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    check_stale_exports(model, dir, &mut diags);
    diags
}

/// W040: the keyring consumers whose export predates the key store's last
/// change (see the module docs). Unreadable metadata is one W040 that says
/// so.
pub(crate) fn check_stale_exports(model: &Model, dir: &Path, diags: &mut Vec<Diagnostic>) {
    let meta = match KeyStoreMeta::load(dir) {
        Ok(meta) => meta,
        Err(err) => {
            diags.push(Diagnostic::new(
                "W040",
                Severity::Warning,
                KEYSTORE_META_FILE,
                format!(
                    "the key store metadata does not read ({err}), so stale keyring exports \
                     cannot be detected; delete the file and export the keyring again"
                ),
            ));
            return;
        }
    };
    let Some(changed) = meta.changed.as_deref() else {
        return;
    };
    for export in &meta.exports {
        if export.written.as_str() >= changed || !resolve(dir, &export.path).is_file() {
            continue;
        }
        diags.push(Diagnostic::new(
            "W040",
            Severity::Warning,
            export.path.clone(),
            format!(
                "the keyring export {} (written {}) is older than the key store's last change \
                 ({changed}): whoever loaded it (Home Assistant, ETS, a visualisation) holds \
                 stale group keys. Run `bussard keys export {} --force` and load it there again, \
                 or delete the file",
                export.path, export.written, export.path
            ),
        ));
    }
    if model.config.home_assistant.is_some() {
        let newest = meta.exports.iter().max_by(|a, b| a.written.cmp(&b.written));
        if newest.is_none_or(|e| e.written.as_str() < changed) {
            let since = match newest {
                Some(e) => format!("after the newest export {} ({})", e.path, e.written),
                None => "and bussard has written no keyring export since".to_string(),
            };
            diags.push(Diagnostic::new(
                "W040",
                Severity::Warning,
                "bussard.toml [home_assistant]",
                format!(
                    "Home Assistant decrypts KNX Data Secure with a keyring, and the key store \
                     changed at {changed}, {since}: run `bussard keys export <file.knxkeys>` and \
                     load the file in Home Assistant's KNX integration, or it keeps old group \
                     keys"
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn tempdir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-keystore-meta-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn model() -> Model {
        Model {
            config: crate::schema::BussardConfig::default(),
            groups: crate::schema::Groups::default(),
            links: crate::schema::Links::default(),
            devices: Default::default(),
        }
    }

    fn codes(model: &Model, dir: &Path) -> Vec<String> {
        let mut diags = Vec::new();
        check_stale_exports(model, dir, &mut diags);
        diags
            .iter()
            .map(|d| format!("{} {}", d.code, d.location))
            .collect()
    }

    #[test]
    fn test_record_export_round_trips_relative_inside_dir() -> TestResult {
        let dir = tempdir("roundtrip")?;
        std::fs::write(dir.join("ha.knxkeys"), "x")?;
        KeyStoreMeta::record_export(&dir, &dir.join("ha.knxkeys"))?;
        KeyStoreMeta::record_export(&dir, &dir.join("ha.knxkeys"))?;
        let meta = KeyStoreMeta::load(&dir)?;
        assert_eq!(meta.exports.len(), 1);
        assert_eq!(meta.exports[0].path, "ha.knxkeys");
        assert_eq!(meta.changed, None);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_check_stale_exports_older_export_is_w040() -> TestResult {
        let dir = tempdir("stale")?;
        std::fs::write(dir.join("ha.knxkeys"), "x")?;
        let meta = KeyStoreMeta {
            changed: Some("2026-10-24T10:00:00Z".into()),
            exports: vec![ExportRecord {
                path: "ha.knxkeys".into(),
                written: "2026-10-20T10:00:00Z".into(),
            }],
        };
        meta.save(&dir)?;
        assert_eq!(codes(&model(), &dir), vec!["W040 ha.knxkeys"]);
        // A fresh export clears it.
        KeyStoreMeta::record_export(&dir, &dir.join("ha.knxkeys"))?;
        assert!(codes(&model(), &dir).is_empty());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_check_stale_exports_home_assistant_without_export_is_w040() -> TestResult {
        let dir = tempdir("ha")?;
        let mut m = model();
        m.config.home_assistant = Some(crate::schema::HomeAssistantConfig {
            url: "http://ha.local:8123".into(),
            token_env: "BUSSARD_HA_TOKEN".into(),
            config_path: None,
        });
        // No recorded change: nothing to say.
        assert!(codes(&m, &dir).is_empty());
        KeyStoreMeta::record_change(&dir)?;
        assert_eq!(codes(&m, &dir), vec!["W040 bussard.toml [home_assistant]"]);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
