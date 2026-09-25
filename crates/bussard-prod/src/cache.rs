//! The parsed-product cache (issue #214): the [`ProductCatalog`] and every
//! parsed [`ApplicationProgram`] of an archive, stored as JSON so the next
//! command reads them back instead of inflating and parsing the XML again.
//!
//! Layout: `<cache>/<key>/catalog.json` and `<cache>/<key>/<application-id>.json`.
//! The key is the SHA-256 of the archive bytes, the selected inner `.knxprod`
//! of a wrapper, the cache format and the identity of the running bussard
//! build (its version and the size and modification time of its executable).
//! So an edited or replaced archive, or a rebuilt bussard whose parser may
//! differ, gets a fresh entry: nothing is ever read from a stale one. The CLI
//! places the cache at `<model dir>/.bussard/products/`.
//!
//! Every failure (an unreadable directory, a truncated or foreign file, a full
//! disk) is a cache miss or a skipped store, never an error: the archive is
//! then parsed as without a cache. Files are written to a temporary name and
//! renamed, so a concurrent reader never sees half a file. At most
//! [`MAX_ENTRIES`] archive entries are kept; the least recently written are
//! removed first.

use std::io::{BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{ApplicationProgram, ProductCatalog};

/// Bumped whenever the stored shape changes incompatibly.
const FORMAT: &str = "bussard-parsed-product-v1";

/// The archive entries kept under one cache directory.
pub const MAX_ENTRIES: usize = 32;

/// The cache entry of one archive.
#[derive(Debug)]
pub struct Store {
    /// The cache root.
    root: PathBuf,
    /// `<root>/<key>`.
    dir: PathBuf,
}

impl Store {
    /// The entry for `archive` (with `inner` selected) under `root`, or
    /// `None` when the archive cannot be read (the parse then reports it).
    pub fn open(root: &Path, archive: &Path, inner: Option<&str>) -> Option<Store> {
        let key = key(archive, inner)?;
        Some(Store {
            root: root.to_path_buf(),
            dir: root.join(key),
        })
    }

    /// The entry's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The cached catalogue, if stored.
    pub fn catalog(&self) -> Option<ProductCatalog> {
        read_json(&self.dir.join("catalog.json"))
    }

    /// Stores the catalogue (best effort).
    pub fn put_catalog(&self, catalog: &ProductCatalog) {
        if !self.dir.is_dir() {
            prune(&self.root);
        }
        write_json(&self.dir, "catalog.json", catalog);
    }

    /// The cached program `id` as parsed (companions not attached), if stored.
    pub fn application(&self, id: &str) -> Option<ApplicationProgram> {
        let name = file_name(id)?;
        let app: ApplicationProgram = read_json(&self.dir.join(name))?;
        (app.id == id).then_some(app)
    }

    /// Stores the parsed program `id` (best effort).
    pub fn put_application(&self, id: &str, app: &ApplicationProgram) {
        if let Some(name) = file_name(id) {
            write_json(&self.dir, &name, app);
        }
    }
}

/// The cache key of `archive`: hex SHA-256 over the format, the build
/// identity, the inner selector and the archive bytes.
fn key(archive: &Path, inner: Option<&str>) -> Option<String> {
    let file = std::fs::File::open(archive).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(FORMAT.as_bytes());
    hasher.update([0]);
    hasher.update(build_identity().as_bytes());
    hasher.update([0]);
    hasher.update(inner.unwrap_or("").as_bytes());
    hasher.update([0]);
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n)?);
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// The running build: the crate version and the executable's size and
/// modification time, so a rebuilt parser never reads a stale entry.
fn build_identity() -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| {
            let modified = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            format!("{}:{modified}", m.len())
        })
        .unwrap_or_default();
    format!("{}:{exe}", env!("CARGO_PKG_VERSION"))
}

/// The file name for program `id`, refusing anything that is not a plain name.
fn file_name(id: &str) -> Option<String> {
    let plain = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !id.starts_with('.');
    plain.then(|| format!("{id}.json"))
}

/// Reads and deserializes `path`, `None` on any failure.
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let file = std::fs::File::open(path).ok()?;
    match serde_json::from_reader(BufReader::with_capacity(1 << 20, file)) {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::debug!(path = %path.display(), %err, "ignoring an unreadable parsed-product cache file");
            None
        }
    }
}

/// Serializes `value` to `dir/name` through a temporary file (best effort).
fn write_json<T: serde::Serialize>(dir: &Path, name: &str, value: &T) {
    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
        {
            let file = std::fs::File::create(&tmp)?;
            let mut writer = BufWriter::with_capacity(1 << 20, file);
            serde_json::to_writer(&mut writer, value).map_err(std::io::Error::other)?;
            std::io::Write::flush(&mut writer)?;
        }
        std::fs::rename(&tmp, dir.join(name))
    })();
    if let Err(err) = result {
        tracing::debug!(dir = %dir.display(), %err, "could not store a parsed-product cache file");
    }
}

/// Removes the least recently written entries so that, with the one about to
/// be created, at most [`MAX_ENTRIES`] remain.
fn prune(root: &Path) {
    let Ok(read) = std::fs::read_dir(root) else {
        return;
    };
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = read
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| {
            let modified = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            (modified, e.path())
        })
        .collect();
    if entries.len() < MAX_ENTRIES {
        return;
    }
    entries.sort();
    let excess = entries.len() + 1 - MAX_ENTRIES;
    for (_, path) in entries.into_iter().take(excess) {
        if let Err(err) = std::fs::remove_dir_all(&path) {
            tracing::debug!(path = %path.display(), %err, "could not prune a parsed-product cache entry");
        }
    }
}
