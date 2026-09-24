//! The single-file `.bussard` bundle (issue #111).
//!
//! A bundle is what an integrator hands a homeowner on a USB stick, and what an
//! owner keeps as a backup: one zip file holding the model, its history and a
//! manifest. It is read by `bussard import` (merged like a `.knxproj`) and by
//! `bussard diff` (compared in memory, nothing written).
//!
//! # Layout
//!
//! ```text
//! manifest.json                      # always the first entry
//! bussard.toml
//! groups.toml
//! bussard.lock
//! tests.toml                         # when present
//! ha.toml                            # when present
//! devices/*.toml
//! .bussard/history/<id>/...          # unless exported with --no-history
//! ```
//!
//! Entries are written in that order, model files and snapshots sorted by
//! path, with a fixed timestamp and permissions, so two exports of the same
//! files differ only in the manifest's `exported_at`.
//!
//! # What a bundle never contains
//!
//! The export copies an allow-list of model files, so nothing else can leak in:
//! `models/`, `vendor/`, `captures/`, keyrings, `.knxproj`, `.knxprod` and
//! `.env` stay on the machine. The manifest lists these exclusions so a
//! recipient can see what is missing on purpose. A reader rejects any entry
//! outside the layout above, so a crafted zip cannot write elsewhere.
//!
//! # Integrity
//!
//! The manifest carries the SHA-256 of every model file and a digest over all
//! of them: SHA-256 of the lines `<file sha256>  <path>\n`, sorted by path
//! (the format `sha256sum` prints). A reader recomputes both and refuses a
//! bundle that does not match.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::history::{HISTORY_DIR, MODEL_FILES, rfc3339};
use crate::loader::{LoadError, Model};

/// The file extension of a bundle.
pub const BUNDLE_EXTENSION: &str = "bussard";

/// The `format` tag every bundle manifest carries.
pub const FORMAT: &str = "bussard-bundle";

/// The bundle layout version this build writes and reads.
pub const FORMAT_VERSION: u32 = 1;

/// The YAML model schema version the bundled files follow.
///
/// Bumped only when the model files change shape incompatibly; a reader refuses
/// a bundle with a newer model version than it knows.
pub const MODEL_VERSION: u32 = 2;

/// The manifest's name inside the zip.
pub const MANIFEST_NAME: &str = "manifest.json";

/// Where `export` records the last bundle it wrote, relative to the model
/// directory. `apply` reads it to hint that the handover file is stale.
pub const LAST_EXPORT: &str = ".bussard/last_export.json";

/// What an export leaves out, listed in every manifest.
pub const EXCLUDED: [&str; 7] = [
    "models/ (cached vendor product models)",
    "vendor/ (vendor product data)",
    "captures/ (bus recordings)",
    "keyrings (*.knxkeys and tool keys)",
    "*.knxproj (ETS projects)",
    "*.knxprod (vendor product files)",
    ".env (passwords and local settings)",
];

/// The largest single entry a reader accepts (a house model is well under a
/// megabyte; this only stops a zip bomb).
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// The most bytes a reader decompresses across all entries.
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// An error writing or reading a bundle.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// An I/O error on the bundle or a model file.
    #[error("bundle: {path}: {source}")]
    Io {
        /// The path being read or written.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The zip container could not be written or read.
    #[error("bundle: zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// The manifest could not be written or parsed as JSON.
    #[error("bundle: manifest.json: {0}")]
    Manifest(#[from] serde_json::Error),
    /// The zip holds no `manifest.json`, so it is not a bussard bundle.
    #[error("bundle: no manifest.json; this is not a .bussard bundle")]
    MissingManifest,
    /// The manifest names a format or version this build cannot read.
    #[error(
        "bundle: format {format} version {format_version} (model version {model_version}) is \
         not supported by this bussard; upgrade bussard to read it"
    )]
    Unsupported {
        /// The manifest's `format` tag.
        format: String,
        /// The manifest's layout version.
        format_version: u32,
        /// The manifest's model schema version.
        model_version: u32,
    },
    /// The zip holds an entry outside the bundle layout.
    #[error("bundle: unexpected entry {name:?}; a bundle holds only model files and history")]
    UnexpectedEntry {
        /// The offending entry name.
        name: String,
    },
    /// An entry is larger than a model file could plausibly be.
    #[error("bundle: entry {name:?} is too large")]
    TooLarge {
        /// The offending entry name.
        name: String,
    },
    /// A model file's hash does not match the manifest.
    #[error("bundle: {path} does not match its SHA-256 in the manifest; the file is damaged")]
    FileDigest {
        /// The model file.
        path: String,
    },
    /// The model digest does not match the manifest, or a listed file is missing.
    #[error("bundle: the model files do not match the manifest digest; the file is damaged")]
    ModelDigest,
    /// A model file is not UTF-8 text.
    #[error("bundle: {path} is not UTF-8 text")]
    NotText {
        /// The model file.
        path: String,
    },
    /// The model files did not load.
    #[error("bundle: the model does not load: {0}")]
    Load(#[from] LoadError),
    /// The directory holds no model files to export.
    #[error("bundle: no model files in {}", dir.display())]
    NoModel {
        /// The model directory.
        dir: PathBuf,
    },
    /// Extraction was asked to write over an existing model.
    #[error("bundle: {} already holds a model; import merges instead", dir.display())]
    TargetHasModel {
        /// The target directory.
        dir: PathBuf,
    },
}

/// The bundle's `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Always [`FORMAT`].
    pub format: String,
    /// The layout version, [`FORMAT_VERSION`] for this build.
    pub format_version: u32,
    /// The model schema version, [`MODEL_VERSION`] for this build.
    pub model_version: u32,
    /// The bussard version that wrote the bundle.
    pub bussard_version: String,
    /// When the bundle was written, RFC3339 in UTC.
    pub exported_at: String,
    /// The ETS project name from `groups.toml`, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// How many devices the model holds.
    pub devices: usize,
    /// How many group addresses the model holds.
    pub group_addresses: usize,
    /// How many link entries (com objects with group addresses) the model holds.
    pub links: usize,
    /// How many history snapshots the bundle carries (0 with `--no-history`).
    pub history_snapshots: usize,
    /// The SHA-256 over all model files (see the module docs for the format).
    pub model_sha256: String,
    /// The SHA-256 of each model file, keyed by its path in the bundle.
    pub files: BTreeMap<String, String>,
    /// What an export never includes.
    pub excluded: Vec<String>,
}

/// A bundle in memory: its manifest, model files and history files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The manifest.
    pub manifest: BundleManifest,
    /// The model files, keyed by model-relative path, exactly as on disk.
    pub model_files: BTreeMap<String, Vec<u8>>,
    /// The history files, keyed by model-relative path
    /// (`.bussard/history/<id>/...`), exactly as on disk.
    pub history_files: BTreeMap<String, Vec<u8>>,
}

/// The record of the last export, stored at [`LAST_EXPORT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastExport {
    /// Where the bundle was written.
    pub path: String,
    /// When, RFC3339 in UTC (the bundle manifest's `exported_at`).
    pub exported_at: String,
    /// The bundle's model digest, to tell whether the model moved since.
    pub model_sha256: String,
}

/// Options for [`Bundle::from_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOptions {
    /// Whether to include `.bussard/history/` snapshots.
    pub include_history: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions {
            include_history: true,
        }
    }
}

impl Bundle {
    /// Collects the model directory `dir` into a bundle, stamping the manifest
    /// with the current time.
    ///
    /// Only the model files (and, with `include_history`, the history
    /// snapshots) are read. The model must load, so a handover file is never a
    /// broken model.
    pub fn from_dir(dir: &Path, options: ExportOptions) -> Result<Bundle, BundleError> {
        let model_files = read_model_files(dir)?;
        if model_files.is_empty() {
            return Err(BundleError::NoModel {
                dir: dir.to_path_buf(),
            });
        }
        let model = Model::load(dir)?;
        let history_files = if options.include_history {
            read_history_files(dir)?
        } else {
            BTreeMap::new()
        };
        let manifest = manifest_for(
            &model,
            &model_files,
            &history_files,
            rfc3339(SystemTime::now()),
        );
        Ok(Bundle {
            manifest,
            model_files,
            history_files,
        })
    }

    /// Serializes the bundle to zip bytes, deterministically: the manifest
    /// first, then model files, then history, each sorted by path, all with a
    /// fixed timestamp.
    pub fn to_zip_bytes(&self) -> Result<Vec<u8>, BundleError> {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644);
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let manifest = format!("{}\n", serde_json::to_string_pretty(&self.manifest)?);
        let entries = std::iter::once((MANIFEST_NAME, manifest.as_bytes()))
            .chain(
                self.model_files
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_slice())),
            )
            .chain(
                self.history_files
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_slice())),
            );
        for (name, bytes) in entries {
            writer.start_file(name, options)?;
            writer.write_all(bytes).map_err(|source| BundleError::Io {
                path: PathBuf::from(name),
                source,
            })?;
        }
        Ok(writer.finish()?.into_inner())
    }

    /// Writes the bundle to `path` atomically (a temporary file in the same
    /// directory, then a rename).
    pub fn write(&self, path: &Path) -> Result<(), BundleError> {
        let bytes = self.to_zip_bytes()?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bundle".to_string());
        let temp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| BundleError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(&temp, &bytes).map_err(|source| BundleError::Io {
            path: temp.clone(),
            source,
        })?;
        fs::rename(&temp, path).map_err(|source| {
            let _ = fs::remove_file(&temp);
            BundleError::Io {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    /// Reads and verifies a bundle file.
    pub fn read(path: &Path) -> Result<Bundle, BundleError> {
        let bytes = fs::read(path).map_err(|source| BundleError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Bundle::from_zip_bytes(&bytes)
    }

    /// Parses and verifies a bundle from zip bytes.
    ///
    /// Every entry must fit the bundle layout, the manifest must name a format
    /// this build reads, and every model file must match its hash.
    pub fn from_zip_bytes(bytes: &[u8]) -> Result<Bundle, BundleError> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        let mut manifest: Option<BundleManifest> = None;
        let mut model_files = BTreeMap::new();
        let mut history_files = BTreeMap::new();
        let mut total: u64 = 0;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = entry.name().to_string();
            if entry.is_dir() {
                continue;
            }
            let kind = classify(&name)
                .ok_or_else(|| BundleError::UnexpectedEntry { name: name.clone() })?;
            if entry.size() > MAX_ENTRY_BYTES {
                return Err(BundleError::TooLarge { name });
            }
            let mut data = Vec::new();
            let read = (&mut entry)
                .take(MAX_ENTRY_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(|source| BundleError::Io {
                    path: PathBuf::from(&name),
                    source,
                })?;
            total += read as u64;
            if read as u64 > MAX_ENTRY_BYTES || total > MAX_TOTAL_BYTES {
                return Err(BundleError::TooLarge { name });
            }
            match kind {
                EntryKind::Manifest => manifest = Some(serde_json::from_slice(&data)?),
                EntryKind::Model => {
                    model_files.insert(name, data);
                }
                EntryKind::History => {
                    history_files.insert(name, data);
                }
            }
        }
        let manifest = manifest.ok_or(BundleError::MissingManifest)?;
        if manifest.format != FORMAT
            || manifest.format_version > FORMAT_VERSION
            || manifest.model_version > MODEL_VERSION
        {
            return Err(BundleError::Unsupported {
                format: manifest.format.clone(),
                format_version: manifest.format_version,
                model_version: manifest.model_version,
            });
        }
        verify(&manifest, &model_files)?;
        Ok(Bundle {
            manifest,
            model_files,
            history_files,
        })
    }

    /// Parses the bundled model in memory, writing nothing.
    pub fn model(&self) -> Result<Model, BundleError> {
        let mut texts = BTreeMap::new();
        for (path, bytes) in &self.model_files {
            let text = String::from_utf8(bytes.clone())
                .map_err(|_| BundleError::NotText { path: path.clone() })?;
            texts.insert(path.clone(), text);
        }
        Ok(Model::from_texts(&texts)?)
    }

    /// Writes the bundled files byte for byte into `dir`, which must not hold
    /// a model yet (no `groups.toml`, no device file). With `include_history`,
    /// the history snapshots are restored too, so `bussard history` and `undo`
    /// work on the copy.
    ///
    /// An existing `bussard.toml` (for example from `bussard init`) is left
    /// untouched: the connection is local, exactly as a re-import keeps it.
    /// Into an empty directory the result is identical to the exported model.
    pub fn extract(&self, dir: &Path, include_history: bool) -> Result<(), BundleError> {
        let existing = read_model_files(dir)?;
        if existing.keys().any(|k| k != crate::loader::CONFIG_FILE) {
            return Err(BundleError::TargetHasModel {
                dir: dir.to_path_buf(),
            });
        }
        let history = include_history.then_some(&self.history_files);
        for (name, bytes) in self.model_files.iter().chain(history.into_iter().flatten()) {
            if existing.contains_key(name) {
                continue;
            }
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|source| BundleError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            fs::write(&path, bytes).map_err(|source| BundleError::Io { path, source })?;
        }
        Ok(())
    }
}

/// Writes a bundle of the model directory `dir` to `out`, records it as the
/// last export and returns its manifest.
pub fn export(
    dir: &Path,
    out: &Path,
    options: ExportOptions,
) -> Result<BundleManifest, BundleError> {
    let bundle = Bundle::from_dir(dir, options)?;
    bundle.write(out)?;
    let record = LastExport {
        path: out.display().to_string(),
        exported_at: bundle.manifest.exported_at.clone(),
        model_sha256: bundle.manifest.model_sha256.clone(),
    };
    let record_path = dir.join(LAST_EXPORT);
    if let Some(parent) = record_path.parent() {
        fs::create_dir_all(parent).map_err(|source| BundleError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let text = format!("{}\n", serde_json::to_string_pretty(&record)?);
    fs::write(&record_path, text).map_err(|source| BundleError::Io {
        path: record_path,
        source,
    })?;
    Ok(bundle.manifest)
}

/// The last export recorded for the model directory `dir`, if any.
pub fn last_export(dir: &Path) -> Option<LastExport> {
    let text = fs::read_to_string(dir.join(LAST_EXPORT)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The model files currently in `dir` (`bussard.toml`, `groups.toml`,
/// `bussard.lock`, `tests.toml`, `ha.toml`, `devices/*.toml`), keyed by
/// model-relative path, as bytes.
pub fn model_files(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, BundleError> {
    read_model_files(dir)
}

/// The model digest of the files currently in `dir`, in the manifest's format.
pub fn current_model_digest(dir: &Path) -> Result<String, BundleError> {
    Ok(model_digest(&read_model_files(dir)?))
}

/// The default bundle path for the model directory `dir`: next to it, named
/// after it and today's date, e.g. `knx` → `./knx-2026-09-23.bussard`.
pub fn default_bundle_path(dir: &Path) -> PathBuf {
    let absolute = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(dir))
            .unwrap_or_else(|_| dir.to_path_buf())
    };
    let name = absolute
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        .unwrap_or("knx")
        .to_string();
    let parent = absolute
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let now = rfc3339(SystemTime::now());
    let date = now.get(..10).unwrap_or("export");
    parent.join(format!("{name}-{date}.{BUNDLE_EXTENSION}"))
}

/// Whether `path` names a bundle (by its `.bussard` extension).
pub fn is_bundle_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(BUNDLE_EXTENSION))
}

/// The digest over a set of model files: SHA-256 of `<sha256>  <path>\n` lines
/// sorted by path.
pub fn model_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        hasher.update(format!("{}  {path}\n", sha256_hex(bytes)).as_bytes());
    }
    hex(&hasher.finalize())
}

// ---------------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------------

/// What an entry in the zip is.
enum EntryKind {
    Manifest,
    Model,
    History,
}

/// Classifies an entry name, or `None` when it is outside the bundle layout.
fn classify(name: &str) -> Option<EntryKind> {
    if name == MANIFEST_NAME {
        return Some(EntryKind::Manifest);
    }
    if is_model_path(name) {
        return Some(EntryKind::Model);
    }
    let rest = name.strip_prefix(HISTORY_DIR)?.strip_prefix('/')?;
    let (id, file) = rest.split_once('/')?;
    let id_ok = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    (id_ok && (file == MANIFEST_NAME || is_model_path(file))).then_some(EntryKind::History)
}

/// Whether a relative path is one of the model files a bundle may carry.
fn is_model_path(name: &str) -> bool {
    if MODEL_FILES.contains(&name) {
        return true;
    }
    let Some(file) = name.strip_prefix("devices/") else {
        return false;
    };
    !file.is_empty()
        && !file.starts_with('.')
        && !file.contains(['/', '\\'])
        && file.ends_with(".toml")
}

/// Reads the model files of `dir`, keyed by model-relative path.
fn read_model_files(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, BundleError> {
    let mut out = BTreeMap::new();
    collect_model_files(dir, "", &mut out)?;
    Ok(out)
}

/// Reads the model files under `base` into `out`, keyed by `prefix` + the
/// model-relative path.
fn collect_model_files(
    base: &Path,
    prefix: &str,
    out: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), BundleError> {
    for name in MODEL_FILES {
        let path = base.join(name);
        if path.is_file() {
            out.insert(format!("{prefix}{name}"), read(&path)?);
        }
    }
    let devices = base.join("devices");
    let Ok(entries) = fs::read_dir(&devices) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let relative = format!("devices/{file}");
        if path.is_file() && is_model_path(&relative) {
            out.insert(format!("{prefix}{relative}"), read(&path)?);
        }
    }
    Ok(())
}

/// Reads every snapshot under `dir/.bussard/history`, keyed by model-relative
/// path.
fn read_history_files(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, BundleError> {
    let mut out = BTreeMap::new();
    let root = dir.join(HISTORY_DIR);
    let Ok(entries) = fs::read_dir(&root) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(id) = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let manifest = path.join(MANIFEST_NAME);
        if !path.is_dir() || !manifest.is_file() {
            continue;
        }
        let prefix = format!("{HISTORY_DIR}/{id}/");
        if classify(&format!("{prefix}{MANIFEST_NAME}")).is_none() {
            continue;
        }
        out.insert(format!("{prefix}{MANIFEST_NAME}"), read(&manifest)?);
        collect_model_files(&path, &prefix, &mut out)?;
    }
    Ok(out)
}

/// Reads one file, naming it in any error.
fn read(path: &Path) -> Result<Vec<u8>, BundleError> {
    fs::read(path).map_err(|source| BundleError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Builds the manifest for a model and its files.
fn manifest_for(
    model: &Model,
    model_files: &BTreeMap<String, Vec<u8>>,
    history_files: &BTreeMap<String, Vec<u8>>,
    exported_at: String,
) -> BundleManifest {
    let history_snapshots = history_files
        .keys()
        .filter(|k| k.ends_with(&format!("/{MANIFEST_NAME}")))
        .count();
    BundleManifest {
        format: FORMAT.to_string(),
        format_version: FORMAT_VERSION,
        model_version: MODEL_VERSION,
        bussard_version: env!("CARGO_PKG_VERSION").to_string(),
        exported_at,
        project: model.groups.project.clone(),
        devices: model.devices.len(),
        group_addresses: model.groups.groups.len(),
        links: model.links.links.values().map(Vec::len).sum(),
        history_snapshots,
        model_sha256: model_digest(model_files),
        files: model_files
            .iter()
            .map(|(path, bytes)| (path.clone(), sha256_hex(bytes)))
            .collect(),
        excluded: EXCLUDED.iter().map(|s| s.to_string()).collect(),
    }
}

/// Checks the model files against the manifest's per-file hashes and digest.
fn verify(
    manifest: &BundleManifest,
    model_files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), BundleError> {
    for (path, bytes) in model_files {
        if manifest.files.get(path) != Some(&sha256_hex(bytes)) {
            return Err(BundleError::FileDigest { path: path.clone() });
        }
    }
    if manifest.files.len() != model_files.len()
        || model_digest(model_files) != manifest.model_sha256
    {
        return Err(BundleError::ModelDigest);
    }
    Ok(())
}

/// The lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A fresh temporary directory for one test.
    fn temp_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-bundle-{tag}-{}-{:?}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// A tiny model directory with one group and one device.
    fn tiny_model(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = temp_dir(tag)?;
        fs::create_dir_all(dir.join("devices"))?;
        fs::write(
            dir.join("groups.toml"),
            "groups = [\n  { address = \"0/0/4\", name = \"Porch light\", dpt = \"1.001\" },\n]\n",
        )?;
        fs::write(
            dir.join("bussard.lock"),
            "version = 1\nsource = \"home.knxproj\"\n",
        )?;
        fs::write(
            dir.join("devices/1.1.4.toml"),
            "address = \"1.1.4\"\nname = \"Actuator\"\n",
        )?;
        // Things that must never enter a bundle.
        fs::create_dir_all(dir.join("models"))?;
        fs::write(dir.join("models/M-0001_A-1.yaml"), "parameters: []\n")?;
        fs::write(dir.join(".env"), "BUSSARD_PROJECT_PASSWORD=secret\n")?;
        fs::write(dir.join("home.knxproj"), "zip")?;
        Ok(dir)
    }

    #[test]
    fn test_classify_accepts_layout_and_rejects_everything_else() {
        for ok in [
            "manifest.json",
            "groups.toml",
            "bussard.lock",
            "tests.toml",
            "ha.toml",
            "devices/1.1.4.toml",
            ".bussard/history/20260922T101112Z-001/manifest.json",
            ".bussard/history/20260922T101112Z-001/devices/1.1.4.toml",
        ] {
            assert!(classify(ok).is_some(), "{ok}");
        }
        for bad in [
            "../evil.toml",
            "devices/../../evil.toml",
            "devices/.hidden.toml",
            "devices/1.1.4.yaml",
            "groups.toml",
            "models/M-1.yaml",
            ".env",
            "home.knxproj",
            ".bussard/history/../x/manifest.json",
            ".bussard/history/id/models/a.yaml",
            "/etc/passwd",
        ] {
            assert!(classify(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn test_bundle_round_trip_verifies_and_excludes() -> TestResult {
        let dir = tiny_model("round-trip")?;
        let bundle = Bundle::from_dir(&dir, ExportOptions::default())?;
        assert_eq!(bundle.manifest.devices, 1);
        assert_eq!(bundle.manifest.group_addresses, 1);
        assert!(bundle.model_files.keys().all(|k| is_model_path(k)));
        assert!(!bundle.model_files.contains_key(".env"));

        let bytes = bundle.to_zip_bytes()?;
        let back = Bundle::from_zip_bytes(&bytes)?;
        assert_eq!(back, bundle);
        assert_eq!(back.model()?, Model::load(&dir)?);

        // Deterministic: the same bundle serializes to the same bytes.
        assert_eq!(bundle.to_zip_bytes()?, bytes);
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_from_zip_bytes_rejects_a_tampered_file() -> TestResult {
        let dir = tiny_model("tamper")?;
        let mut bundle = Bundle::from_dir(&dir, ExportOptions::default())?;
        bundle
            .model_files
            .insert("groups.toml".to_string(), b"groups = []\n".to_vec());
        let err = Bundle::from_zip_bytes(&bundle.to_zip_bytes()?);
        assert!(
            matches!(err, Err(BundleError::FileDigest { .. })),
            "{err:?}"
        );
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_from_zip_bytes_rejects_an_unexpected_entry() -> TestResult {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer.start_file("../evil.toml", zip::write::SimpleFileOptions::default())?;
        writer.write_all(b"x")?;
        let bytes = writer.finish()?.into_inner();
        let err = Bundle::from_zip_bytes(&bytes);
        assert!(
            matches!(err, Err(BundleError::UnexpectedEntry { .. })),
            "{err:?}"
        );
        Ok(())
    }

    #[test]
    fn test_export_records_last_export_and_extract_refuses_a_model() -> TestResult {
        let dir = tiny_model("export")?;
        let out = dir.join("house.bussard");
        let manifest = export(&dir, &out, ExportOptions::default())?;
        let record = last_export(&dir).ok_or("no last export")?;
        assert_eq!(record.model_sha256, manifest.model_sha256);
        assert_eq!(current_model_digest(&dir)?, manifest.model_sha256);

        let bundle = Bundle::read(&out)?;
        let err = bundle.extract(&dir, true);
        assert!(
            matches!(err, Err(BundleError::TargetHasModel { .. })),
            "{err:?}"
        );
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_default_bundle_path_sits_next_to_the_model() {
        // Built from the temp dir so the path is absolute on every platform
        // (a bare `/srv/house` is relative on Windows).
        let house = std::env::temp_dir().join("srv").join("house");
        let path = default_bundle_path(&house.join("knx"));
        assert_eq!(path.parent(), Some(house.as_path()));
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(
            name.starts_with("knx-") && name.ends_with(".bussard"),
            "{name}"
        );
        assert!(is_bundle_path(&path));
    }
}
