//! Loading and saving the model directory.
//!
//! The files and their shapes are specified in `docs/model-format.md`:
//! `bussard.toml`, `groups.toml`, `devices/<address>.toml`, the generated
//! `bussard.lock`, plus the optional `tests.toml` and `ha.toml` (read by their
//! own modules). [`Model::load`] joins each device file with its lock entry;
//! [`Model::save`] splits them again, edits existing files in place so
//! comments and untouched lines survive, and rewrites the lock.
//!
//! Every write is atomic (staged temp file plus rename), and a file whose
//! contents would not change is not touched at all.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::address::IndividualAddress;
use crate::emit;
use crate::files::{self, GroupsFile, LOCK_VERSION, LockDevice, LockFile};
use crate::param_model::ProductModels;
use crate::schema::{BussardConfig, Group, Groups, Link, Links, Range};
use crate::toml_io::{self, ParseError};

/// The connection and lint settings file.
pub const CONFIG_FILE: &str = "bussard.toml";
/// The group-address plan.
pub const GROUPS_FILE: &str = "groups.toml";
/// The generated lock file.
pub const LOCK_FILE: &str = "bussard.lock";
/// The directory holding one file per device.
pub const DEVICES_DIR: &str = "devices";
/// The extension of a device file (`devices/1.1.47.toml`).
pub const DEVICE_EXTENSION: &str = "toml";

/// The top-level files a snapshot, a bundle and the change fingerprint cover
/// (besides `devices/*.toml`).
pub const MODEL_FILES: [&str; 5] = [CONFIG_FILE, GROUPS_FILE, LOCK_FILE, "tests.toml", "ha.toml"];

/// Whether a model-relative path is a device file (`devices/<name>.toml`).
pub fn is_device_path(rel: &str) -> bool {
    device_stem(rel).is_some()
}

/// The stem of a device file path (`devices/1.1.4.toml` → `1.1.4`).
fn device_stem(rel: &str) -> Option<&str> {
    rel.strip_prefix("devices/")?
        .strip_suffix(".toml")
        .filter(|stem| !stem.is_empty() && !stem.contains('/') && !stem.starts_with('.'))
}

/// An error loading the model from disk.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// An I/O error reading a file or directory.
    #[error("reading {path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A file was not valid TOML or did not match its schema. The rendered
    /// error carries the caret, the message and, where a rule matched, a
    /// `help:` line.
    #[error("{0}")]
    Parse(Box<ParseError>),
    /// Two device files declare the same individual `address`.
    #[error(
        "duplicate device address {address}: declared in both {first} and {second} \
         (each device address must be unique across devices/*.toml)"
    )]
    DuplicateDeviceAddress {
        /// The colliding individual address.
        address: IndividualAddress,
        /// The first file that declared it (sorted order).
        first: PathBuf,
        /// The second file that declared it.
        second: PathBuf,
    },
    /// `bussard.lock` carries a format version this build does not read.
    #[error(
        "{path}: lock format version {version} is not supported (this bussard reads version \
         {LOCK_VERSION} only); regenerate it with `bussard import <export> --dir <dir>`"
    )]
    LockVersion {
        /// The lock file.
        path: PathBuf,
        /// The version it declares.
        version: u32,
    },
    /// The directory holds the retired YAML model and no TOML model.
    #[error(
        "{dir} holds a YAML model (groups.yaml, links.yaml, devices/*.yaml); bussard now \
         reads TOML (bussard.toml, groups.toml, devices/<address>.toml, bussard.lock, see \
         docs/model-format.md). Re-import the project into an empty directory."
    )]
    LegacyYaml {
        /// The model directory.
        dir: PathBuf,
    },
}

impl From<ParseError> for LoadError {
    fn from(e: ParseError) -> Self {
        LoadError::Parse(Box::new(e))
    }
}

/// An error saving the model to disk.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    /// An I/O error writing a file or creating a directory.
    #[error("writing {path}: {source}")]
    Io {
        /// The path being written.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Serializing a value to TOML failed.
    #[error("serializing {path}: {message}")]
    Serialize {
        /// The target file.
        path: PathBuf,
        /// The underlying error.
        message: String,
    },
    /// Links name a device the model does not hold: they live in the device's
    /// own file, so there is nowhere to write them.
    #[error(
        "links reference device {address}, which has no device in the model; add the device \
         (devices/{address}.toml) or drop the links"
    )]
    OrphanLinks {
        /// The address the links name.
        address: IndividualAddress,
    },
    /// Writing the temporary file used to stage an atomic save failed.
    ///
    /// The save is aborted before the real file is touched, so the previous
    /// contents of `path` (if any) are left intact. `temp` names the staging
    /// file that could not be written; check that the model's directory is
    /// writable and has free space.
    #[error("staging {path} via temporary file {temp}: {source}")]
    TempWrite {
        /// The intended final path, left untouched.
        path: PathBuf,
        /// The temporary staging file that could not be written.
        temp: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Renaming the staged temporary file over the target failed.
    ///
    /// The staged data is complete but could not be moved into place. `path`
    /// still holds its previous contents (never a half-written file); the
    /// stale `temp` file is best-effort removed. A cross-device staging
    /// directory or a permission change on `path` are the usual causes.
    #[error("committing {path} by renaming {temp}: {source}")]
    Rename {
        /// The intended final path, left untouched.
        path: PathBuf,
        /// The temporary staging file that could not be renamed into place.
        temp: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// The fully loaded KNX model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    /// Connection configuration from `bussard.toml`.
    pub config: BussardConfig,
    /// The group-address plan from `groups.toml` (plus the lock's `source`).
    pub groups: Groups,
    /// The links, gathered from every device file's object entries.
    pub links: Links,
    /// Devices from `devices/*.toml` joined with `bussard.lock`, keyed by
    /// individual address, with the source file stem recorded for diagnostics.
    pub devices: BTreeMap<IndividualAddress, LoadedDevice>,
}

/// A device together with the filename it was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedDevice {
    /// The device definition.
    pub device: Device,
    /// The file stem (filename without `.toml`) it was read from. A device
    /// file is named by its address, so this is the address; validation
    /// reports `E002` when it is not.
    pub file_stem: String,
}

use crate::schema::Device;

/// The raw texts of a model, keyed by model-relative path.
struct Sources {
    /// The directory the paths are relative to, for error messages.
    base: PathBuf,
    files: BTreeMap<String, String>,
}

impl Sources {
    fn path(&self, rel: &str) -> PathBuf {
        self.base.join(rel)
    }
}

/// Reads a file, returning `None` when it does not exist.
fn read_optional(path: &Path) -> Result<Option<String>, LoadError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(LoadError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The `*.toml` file names in a `devices/` directory, sorted.
fn list_device_files(devices_dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = match fs::read_dir(devices_dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
            .filter(|n| is_device_path(&format!("devices/{n}")))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// Parses `bussard.lock` text.
pub(crate) fn parse_lock(path: &Path, text: &str) -> Result<LockFile, LoadError> {
    let lock: LockFile = toml_io::parse(path, text)?;
    if lock.version != LOCK_VERSION {
        return Err(LoadError::LockVersion {
            path: path.to_path_buf(),
            version: lock.version,
        });
    }
    Ok(lock)
}

/// Parses `groups.toml` text into the in-memory plan (duplicates: last wins;
/// validation reports them as E020).
pub(crate) fn parse_groups(path: &Path, text: &str) -> Result<Groups, LoadError> {
    let file: GroupsFile = toml_io::parse(path, text)?;
    let mut groups = Groups {
        project: file.project,
        ..Groups::default()
    };
    for r in file.ranges {
        groups
            .ranges
            .insert(r.address.trim().to_string(), Range { name: r.name });
    }
    for g in file.groups {
        groups.groups.insert(
            g.address,
            Group {
                name: g.name,
                dpt: g.dpt,
                description: g.description,
                protected: g.protected,
                secure: g.secure,
            },
        );
    }
    Ok(groups)
}

/// The `models/` directory as `Model::load` sees it: every entry's name, size
/// and modification time. The product models translate enum labels, so a
/// change there must miss the memo even when the model files are unchanged.
fn models_fingerprint(dir: &Path) -> ModelsFingerprint {
    let mut out: ModelsFingerprint = crate::param_model::models_dirs(dir)
        .into_iter()
        .filter_map(|d| fs::read_dir(d).ok())
        .flat_map(|rd| rd.flatten())
        .map(|e| {
            let meta = e.metadata().ok();
            (
                e.file_name().to_string_lossy().into_owned(),
                meta.as_ref().map(fs::Metadata::len).unwrap_or_default(),
                meta.and_then(|m| m.modified().ok()),
            )
        })
        .collect();
    out.sort();
    out
}

/// The process-wide memo behind [`Model::load`] (issue #214): one command
/// used to parse the same model three to five times (the command, the
/// history capture, the connection config). A load whose directory, file
/// texts and `models/` fingerprint all equal a memoized one returns a clone
/// of that model instead of parsing again; any edit to any file misses, so a
/// command that saves and reloads sees its own write.
mod memo {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use super::Model;

    /// Parses so far (see [`Model::parse_count`]).
    pub(super) static PARSES: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    thread_local! {
        /// This thread's parses: what a unit test counts, unaffected by
        /// tests running in parallel threads.
        pub(super) static THREAD_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// The memoized loads kept, most recent last: the working model plus a
    /// history snapshot or two.
    const KEEP: usize = 4;

    /// One memoized load.
    struct Entry {
        dir: PathBuf,
        files: BTreeMap<String, String>,
        models: super::ModelsFingerprint,
        model: Model,
    }

    static ENTRIES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

    /// The memoized model for exactly these inputs.
    pub(super) fn get(
        dir: &Path,
        files: &BTreeMap<String, String>,
        models: &super::ModelsFingerprint,
    ) -> Option<Model> {
        let entries = ENTRIES.lock().ok()?;
        entries
            .iter()
            .find(|e| e.dir == dir && &e.files == files && &e.models == models)
            .map(|e| e.model.clone())
    }

    /// Memoizes a freshly parsed model.
    pub(super) fn put(
        dir: &Path,
        files: BTreeMap<String, String>,
        models: super::ModelsFingerprint,
        model: &Model,
    ) {
        let Ok(mut entries) = ENTRIES.lock() else {
            return;
        };
        entries.retain(|e| e.dir != dir);
        if entries.len() >= KEEP {
            entries.remove(0);
        }
        entries.push(Entry {
            dir: dir.to_path_buf(),
            files,
            models,
            model: model.clone(),
        });
    }
}

/// See [`models_fingerprint`].
type ModelsFingerprint = Vec<(String, u64, Option<std::time::SystemTime>)>;

/// Builds the model from its sources. With `models_dir`, the product models
/// of the applications the lock pins are read from its `models/` to translate
/// enum labels to codes.
fn assemble(sources: &Sources, models_dir: Option<&Path>) -> Result<Model, LoadError> {
    memo::PARSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    memo::THREAD_PARSES.with(|n| n.set(n.get() + 1));
    let config: BussardConfig = match sources.files.get(CONFIG_FILE) {
        Some(text) => toml_io::parse(&sources.path(CONFIG_FILE), text)?,
        None => BussardConfig::default(),
    };
    let mut groups = match sources.files.get(GROUPS_FILE) {
        Some(text) => parse_groups(&sources.path(GROUPS_FILE), text)?,
        None => Groups::default(),
    };
    let lock = match sources.files.get(LOCK_FILE) {
        Some(text) => parse_lock(&sources.path(LOCK_FILE), text)?,
        None => LockFile::default(),
    };
    groups.imported_from = lock.source.clone();
    let lock_by_address: BTreeMap<IndividualAddress, &LockDevice> =
        lock.devices.iter().map(|d| (d.address, d)).collect();
    let models = models_dir.map(|dir| {
        ProductModels::load_apps(
            dir,
            lock.devices.iter().filter_map(|d| d.application.as_deref()),
        )
    });

    let mut devices = BTreeMap::new();
    let mut links: BTreeMap<IndividualAddress, Vec<Link>> = BTreeMap::new();
    let mut source_file: BTreeMap<IndividualAddress, PathBuf> = BTreeMap::new();
    for (rel, text) in &sources.files {
        let Some(stem) = device_stem(rel) else {
            continue;
        };
        let path = sources.path(rel);
        // The lock entry is found by the address the file declares.
        let (mut device, device_links) =
            files::join_device(&path, text, &lock_by_address, models.as_ref())?;
        device.lock.language = lock.language.clone();
        device.lock.product_entry = device.lock.product_sha256.as_deref().and_then(|sha| {
            lock.products
                .iter()
                .find(|p| p.sha256.eq_ignore_ascii_case(sha))
                .cloned()
        });
        if let Some(first) = source_file.get(&device.address) {
            return Err(LoadError::DuplicateDeviceAddress {
                address: device.address,
                first: first.clone(),
                second: path,
            });
        }
        source_file.insert(device.address, path);
        if !device_links.is_empty() {
            links.insert(device.address, device_links);
        }
        devices.insert(
            device.address,
            LoadedDevice {
                device,
                file_stem: stem.to_string(),
            },
        );
    }

    Ok(Model {
        config,
        groups,
        links: Links { links },
        devices,
    })
}

impl Model {
    /// Loads the model from a directory.
    ///
    /// Reads `bussard.toml`, `groups.toml` and `bussard.lock` (each optional)
    /// and every `devices/*.toml`, joining each device file with its lock
    /// entry. Two device files declaring the same `address` are a hard load
    /// error naming both files. A directory that holds only the retired YAML
    /// model is refused with [`LoadError::LegacyYaml`] rather than read as
    /// empty.
    pub fn load(dir: &Path) -> Result<Self, LoadError> {
        let mut files = BTreeMap::new();
        for name in [CONFIG_FILE, GROUPS_FILE, LOCK_FILE] {
            if let Some(text) = read_optional(&dir.join(name))? {
                files.insert(name.to_string(), text);
            }
        }
        let devices_dir = dir.join(DEVICES_DIR);
        for name in list_device_files(&devices_dir) {
            let path = devices_dir.join(&name);
            if let Some(text) = read_optional(&path)? {
                files.insert(format!("{DEVICES_DIR}/{name}"), text);
            }
        }
        if files.is_empty()
            && ["groups.yaml", "links.yaml", "bussard.yaml"]
                .iter()
                .any(|f| dir.join(f).is_file())
        {
            return Err(LoadError::LegacyYaml {
                dir: dir.to_path_buf(),
            });
        }
        let models = models_fingerprint(dir);
        if let Some(model) = memo::get(dir, &files, &models) {
            return Ok(model);
        }
        let sources = Sources {
            base: dir.to_path_buf(),
            files,
        };
        let model = assemble(&sources, Some(dir))?;
        memo::put(dir, sources.files, models, &model);
        Ok(model)
    }

    /// How many times this process has parsed a model from its files: the
    /// loads [`Model::load`] could not answer from its memo, plus every
    /// [`Model::from_texts`]. A debug counter for the start-up budget
    /// (issue #214); `--timing` prints it.
    pub fn parse_count() -> usize {
        memo::PARSES.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Parses a model from in-memory file contents, keyed by model-relative path
    /// (`bussard.toml`, `groups.toml`, `bussard.lock`, `devices/<address>.toml`).
    ///
    /// The in-memory twin of [`Model::load`], used to read a `.bussard` bundle
    /// without extracting it. Keys outside those shapes are ignored.
    pub fn from_texts(files: &BTreeMap<String, String>) -> Result<Self, LoadError> {
        let files = files
            .iter()
            .filter(|(k, _)| {
                matches!(k.as_str(), CONFIG_FILE | GROUPS_FILE | LOCK_FILE) || is_device_path(k)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assemble(
            &Sources {
                base: PathBuf::new(),
                files,
            },
            None,
        )
    }

    /// The language `bussard.lock` records: the one the devices carry (see
    /// [`crate::schema::DeviceLock::language`]).
    pub fn lock_language(&self) -> Option<&str> {
        self.devices
            .values()
            .find_map(|l| l.device.lock.language.as_deref())
    }

    /// The lock entries this model writes, sorted by address.
    fn lock_entries(&self) -> Vec<LockDevice> {
        self.devices
            .values()
            .filter_map(|l| files::lock_entry(&l.device))
            .collect()
    }

    /// Refuses links for devices the model does not hold (they have no file).
    fn check_orphan_links(&self) -> Result<(), SaveError> {
        for (address, links) in &self.links.links {
            if !links.is_empty() && !self.devices.contains_key(address) {
                return Err(SaveError::OrphanLinks { address: *address });
            }
        }
        Ok(())
    }

    /// Renders every file, editing the existing texts in `existing` in place.
    fn render(
        &self,
        existing: &BTreeMap<String, String>,
        models: Option<&ProductModels>,
    ) -> Result<BTreeMap<String, String>, SaveError> {
        self.check_orphan_links()?;
        let mut out = BTreeMap::new();
        out.insert(
            CONFIG_FILE.to_string(),
            match existing.get(CONFIG_FILE) {
                Some(text) => text.clone(),
                None => emit::render_config(Path::new(CONFIG_FILE), &self.config)?,
            },
        );
        out.insert(
            GROUPS_FILE.to_string(),
            emit::render_groups(
                Path::new(GROUPS_FILE),
                &self.groups,
                existing.get(GROUPS_FILE).map(String::as_str),
            )?,
        );
        let mut locks = self.lock_entries();
        let products = files::lock_products(
            &mut locks,
            self.devices.values().map(|l| &l.device),
            existing.get(LOCK_FILE).map(String::as_str),
        );
        let by_address: BTreeMap<IndividualAddress, &LockDevice> =
            locks.iter().map(|l| (l.address, l)).collect();
        out.insert(
            LOCK_FILE.to_string(),
            emit::render_lock(
                self.groups.imported_from.as_deref(),
                self.lock_language(),
                &products,
                &locks,
            ),
        );
        let no_links: Vec<Link> = Vec::new();
        for (address, loaded) in &self.devices {
            let rel = format!("{DEVICES_DIR}/{address}.{DEVICE_EXTENSION}");
            let links = self.links.links.get(address).unwrap_or(&no_links);
            let text = emit::render_device(
                Path::new(&rel),
                &loaded.device,
                links,
                by_address.get(address).copied(),
                existing.get(&rel).map(String::as_str),
                models,
            );
            out.insert(rel, text);
        }
        Ok(out)
    }

    /// Renders the model to the exact file contents a save into an empty
    /// directory would write, keyed by model-relative path, without touching
    /// the disk. Used by `bussard diff --raw` and the bundle writer.
    pub fn to_texts(&self) -> Result<BTreeMap<String, String>, SaveError> {
        self.render(&BTreeMap::new(), None)
    }

    /// Saves the model to a directory.
    ///
    /// Each device is written to `devices/<address>.toml` and the lock to
    /// `bussard.lock`. Files that exist are edited in place (comments and the
    /// formatting of untouched entries survive); a file whose contents would
    /// not change is not rewritten. `bussard.toml` is user-owned: it is
    /// written only when absent. `bussard.lock` is written when the model has
    /// generated data or a lock already exists. Stale device files are left
    /// alone here; see [`Model::save_pruning`].
    pub fn save(&self, dir: &Path) -> Result<(), SaveError> {
        fs::create_dir_all(dir).map_err(|source| SaveError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let devices_dir = dir.join(DEVICES_DIR);
        fs::create_dir_all(&devices_dir).map_err(|source| SaveError::Io {
            path: devices_dir.clone(),
            source,
        })?;
        let mut existing = BTreeMap::new();
        let mut rels: Vec<String> = vec![
            CONFIG_FILE.to_string(),
            GROUPS_FILE.to_string(),
            LOCK_FILE.to_string(),
        ];
        rels.extend(
            self.devices
                .keys()
                .map(|a| format!("{DEVICES_DIR}/{a}.{DEVICE_EXTENSION}")),
        );
        for rel in &rels {
            if let Ok(text) = fs::read_to_string(dir.join(rel)) {
                existing.insert(rel.clone(), text);
            }
        }
        let models = ProductModels::load_apps(
            dir,
            self.devices.values().filter_map(|l| {
                l.device
                    .product
                    .as_ref()
                    .and_then(|p| p.application_ref.as_deref())
            }),
        );
        let rendered = self.render(&existing, Some(&models))?;
        let has_lock_data = self.groups.imported_from.is_some() || !self.lock_entries().is_empty();
        for (rel, text) in &rendered {
            if rel == LOCK_FILE && !has_lock_data && !existing.contains_key(LOCK_FILE) {
                continue;
            }
            if existing.get(rel) == Some(text) {
                continue;
            }
            atomic_write(&dir.join(rel), text.as_bytes())?;
        }
        Ok(())
    }

    /// Saves the model, then prunes device files whose address is not in the
    /// saved set and reports pruned/renamed files on `stderr` (issue #18).
    ///
    /// A device file is named by its address, so any other `*.toml` in
    /// `devices/` is stale: when its name still starts with the address of a
    /// device in the model (`1.1.4-old-name.toml`) it is reported as renamed,
    /// otherwise as pruned.
    pub fn save_pruning(&self, dir: &Path) -> Result<PruneReport, SaveError> {
        let kept: std::collections::BTreeSet<String> = self
            .devices
            .keys()
            .map(|a| format!("{a}.{DEVICE_EXTENSION}"))
            .collect();
        let devices_dir = dir.join(DEVICES_DIR);
        let existing = list_device_files(&devices_dir);

        self.save(dir)?;

        let mut report = PruneReport::default();
        for name in &existing {
            if kept.contains(name) {
                continue;
            }
            let path = devices_dir.join(name);
            fs::remove_file(&path).map_err(|source| SaveError::Io {
                path: path.clone(),
                source,
            })?;
            match stale_file_rename_target(name, &self.devices) {
                Some(new_name) => report.renamed.push((name.clone(), new_name)),
                None => report.pruned.push(name.clone()),
            }
        }

        for (old, new) in &report.renamed {
            eprintln!("renamed device file devices/{old} → devices/{new} (same address)");
        }
        for name in &report.pruned {
            eprintln!("pruned stale device file devices/{name} (device no longer in the project)");
        }
        Ok(report)
    }
}

/// If a stale device filename's leading address matches a device still in
/// the model, returns that device's file name (a rename), else `None`.
fn stale_file_rename_target(
    stale_name: &str,
    devices: &BTreeMap<IndividualAddress, LoadedDevice>,
) -> Option<String> {
    let stem = stale_name.strip_suffix(".toml")?;
    let addr: IndividualAddress = stem.split('-').next()?.parse().ok()?;
    devices
        .contains_key(&addr)
        .then(|| format!("{addr}.{DEVICE_EXTENSION}"))
        .filter(|new_name| new_name != stale_name)
}

/// The result of a pruning save: which device files were removed or renamed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Device filenames (relative to `devices/`) removed because their device
    /// left the project.
    pub pruned: Vec<String>,
    /// `(old, new)` device filenames replaced because the file did not carry
    /// the device's address as its name.
    pub renamed: Vec<(String, String)>,
}

/// Loads only `<dir>/bussard.toml`, returning the default config when the file
/// is absent. Cheaper than [`Model::load`] for a caller that needs just the
/// connection settings (the CLI's `connection.keyring` default, issue #189).
pub fn load_config(dir: &Path) -> Result<BussardConfig, LoadError> {
    let path = dir.join(CONFIG_FILE);
    match read_optional(&path)? {
        Some(text) => Ok(toml_io::parse(&path, &text)?),
        None => Ok(BussardConfig::default()),
    }
}

/// The language `bussard import` should derive texts in for the model in
/// `dir`: `[import] language` from `bussard.toml`, else the `language` the
/// existing `bussard.lock` records, else `None` (the import chooses). Files
/// that are missing or do not parse count as absent.
pub fn import_language(dir: &Path) -> Option<String> {
    let configured = load_config(dir)
        .ok()
        .and_then(|c| c.import)
        .and_then(|i| i.language)
        .filter(|l| !l.trim().is_empty());
    configured.or_else(|| {
        let path = dir.join(LOCK_FILE);
        let text = fs::read_to_string(&path).ok()?;
        parse_lock(&path, &text).ok()?.language
    })
}

/// Loads a `groups.toml` from an explicit path, returning an empty plan when
/// the file is absent.
///
/// `Model::load` always reads `<dir>/groups.toml`; the scaffolder needs to read
/// (and extend) whichever file `--out` names, so it goes through here.
pub fn load_groups(path: &Path) -> Result<Groups, LoadError> {
    match read_optional(path)? {
        Some(text) => parse_groups(path, &text),
        None => Ok(Groups::default()),
    }
}

/// Writes a `groups.toml` to an explicit path, editing the existing file in
/// place when there is one.
///
/// Crash-safe like every other model write (staged temp file plus rename).
pub fn save_groups(path: &Path, groups: &Groups) -> Result<(), SaveError> {
    let existing = fs::read_to_string(path).ok();
    let text = emit::render_groups(path, groups, existing.as_deref())?;
    if existing.as_deref() == Some(text.as_str()) {
        return Ok(());
    }
    atomic_write(path, text.as_bytes())
}

/// Atomically writes `contents` to `path`.
///
/// The bytes are first written to a temporary file in the **same directory**
/// (so the final `rename` stays on one filesystem and is atomic), then renamed
/// over `path`. An interrupted or failed write therefore never truncates or
/// corrupts an existing committed config: `path` either still holds its old
/// contents or holds the complete new contents, never a partial mix.
///
/// On any failure the temporary file is best-effort removed so a crash mid-save
/// does not litter the directory with `.tmp` debris.
///
/// This is the single funnel every model writer routes through, so callers such
/// as `bussard assign`/`import` get crash-safe saves transparently.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), SaveError> {
    // Stage the temp file alongside the target. The file stem is embedded so
    // concurrent saves of different files in the same directory don't collide,
    // and the process id keeps two processes from clobbering each other's temp.
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "model".to_string());
    let temp = match path.parent() {
        Some(dir) => dir.join(format!(".{file_name}.{}.tmp", std::process::id())),
        None => PathBuf::from(format!(".{file_name}.{}.tmp", std::process::id())),
    };

    if let Err(source) = fs::write(&temp, contents) {
        // Best-effort cleanup; ignore errors since we're already reporting one.
        let _ = fs::remove_file(&temp);
        return Err(SaveError::TempWrite {
            path: path.to_path_buf(),
            temp,
            source,
        });
    }

    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(source) => {
            let _ = fs::remove_file(&temp);
            Err(SaveError::Rename {
                path: path.to_path_buf(),
                temp,
                source,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Device, Group};

    type R = Result<(), Box<dyn std::error::Error>>;

    fn tmp_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-loader-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        Ok(dir)
    }

    /// A tiny one-device model.
    fn small_model() -> Result<Model, Box<dyn std::error::Error>> {
        let addr: IndividualAddress = "1.1.4".parse()?;
        let mut groups = Groups::default();
        groups.groups.insert(
            "3/0/4".parse()?,
            Group {
                name: "Jalousie Wohnen".to_string(),
                dpt: Some("1.008".parse()?),
                ..Default::default()
            },
        );
        let device = Device {
            address: addr,
            name: "Jalousieaktor Wohnen".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects: BTreeMap::new(),
            security: None,
            application_override: None,
            lock: Default::default(),
        };
        let mut devices = BTreeMap::new();
        devices.insert(
            addr,
            LoadedDevice {
                device,
                file_stem: addr.to_string(),
            },
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups,
            links: Links::default(),
            devices,
        })
    }

    #[test]
    fn save_then_load_roundtrips() -> R {
        let dir = tmp_dir("roundtrip")?;
        let model = small_model()?;
        model.save(&dir)?;
        assert_eq!(Model::load(&dir)?, model);
        let first = fs::read_to_string(dir.join(GROUPS_FILE))?;
        model.save(&dir)?;
        assert_eq!(first, fs::read_to_string(dir.join(GROUPS_FILE))?);
        // Nothing generated, so no lock is written.
        assert!(!dir.join(LOCK_FILE).exists());
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// This thread's model parses so far.
    fn thread_parses() -> usize {
        memo::THREAD_PARSES.with(std::cell::Cell::get)
    }

    #[test]
    fn test_load_memo_parses_once_and_misses_on_an_edit() -> R {
        let dir = tmp_dir("memo")?;
        let model = small_model()?;
        model.save(&dir)?;
        let before = thread_parses();
        let first = Model::load(&dir)?;
        let again = Model::load(&dir)?;
        assert_eq!(first, again);
        assert_eq!(thread_parses() - before, 1, "the second load is memoized");
        // Any edit to a model file misses the memo.
        let groups = dir.join(GROUPS_FILE);
        let text = fs::read_to_string(&groups)?;
        fs::write(&groups, format!("{text}\n# edited\n"))?;
        Model::load(&dir)?;
        assert_eq!(
            thread_parses() - before,
            2,
            "an edited file is parsed again"
        );
        // So does a change under `.bussard/models/` (the enum label
        // translations).
        let models = dir.join(crate::param_model::MODELS_DIR);
        fs::create_dir_all(&models)?;
        fs::write(models.join("extra.yaml"), "# nothing\n")?;
        Model::load(&dir)?;
        assert_eq!(
            thread_parses() - before,
            3,
            "a .bussard/models/ change is parsed again"
        );
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn save_creates_bussard_toml_when_absent() -> R {
        let dir = tmp_dir("config-fresh")?;
        small_model()?.save(&dir)?;
        let text = fs::read_to_string(dir.join(CONFIG_FILE))?;
        assert!(text.starts_with("# bussard.toml"), "{text}");
        assert!(text.contains("[connection]"), "{text}");
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn save_leaves_existing_bussard_toml_byte_untouched() -> R {
        let dir = tmp_dir("config-owned")?;
        fs::create_dir_all(&dir)?;
        let hand = "# mine\n[connection]\ntransport = \"tunnel\"\ngateway = \"10.0.0.9:3671\"\n";
        fs::write(dir.join(CONFIG_FILE), hand)?;
        small_model()?.save_pruning(&dir)?;
        assert_eq!(fs::read_to_string(dir.join(CONFIG_FILE))?, hand);
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn save_pruning_removes_stale_and_renamed_files() -> R {
        let dir = tmp_dir("prune")?;
        let mut model = small_model()?;
        fs::create_dir_all(dir.join(DEVICES_DIR))?;
        // An old slug-named file for the same address is a rename.
        fs::write(
            dir.join("devices/1.1.4-old.toml"),
            "address = \"1.1.9\"\nname = \"x\"\n",
        )?;
        let report = model.save_pruning(&dir)?;
        assert_eq!(
            report.renamed,
            vec![("1.1.4-old.toml".to_string(), "1.1.4.toml".to_string())]
        );
        assert_eq!(
            list_device_files(&dir.join(DEVICES_DIR)),
            vec!["1.1.4.toml"]
        );
        model.devices.clear();
        let report = model.save_pruning(&dir)?;
        assert_eq!(report.pruned, vec!["1.1.4.toml"]);
        assert!(list_device_files(&dir.join(DEVICES_DIR)).is_empty());
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn orphan_links_are_refused() -> R {
        let mut model = small_model()?;
        model.links.links.insert(
            "1.1.99".parse()?,
            vec![Link {
                object: 1,
                name: None,
                send: None,
                listen: vec![],
            }],
        );
        assert!(matches!(
            model.to_texts(),
            Err(SaveError::OrphanLinks { .. })
        ));
        Ok(())
    }

    #[test]
    fn atomic_write_failure_leaves_original_intact() -> R {
        let dir = tmp_dir("atomic")?;
        fs::create_dir_all(&dir)?;
        let target = dir.join(GROUPS_FILE);
        fs::write(&target, "groups = []\n")?;
        let doomed = dir.join("missing").join(GROUPS_FILE);
        let err = atomic_write(&doomed, b"new");
        assert!(matches!(err, Err(SaveError::TempWrite { .. })), "{err:?}");
        assert_eq!(fs::read_to_string(&target)?, "groups = []\n");
        let stray: Vec<_> = fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(stray.is_empty());
        atomic_write(&target, b"short")?;
        assert_eq!(fs::read_to_string(&target)?, "short");
        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
