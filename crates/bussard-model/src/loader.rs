//! Loading and saving the YAML model.
//!
//! All YAML (de)serialization is isolated here (plus the `Serialize`/
//! `Deserialize` impls on the domain types), so the underlying crate
//! (`serde_norway`) is swappable.
//!
//! Duplicate map keys are rejected: each file is first parsed into a
//! [`serde_norway::Value`], which errors on any duplicate key at any depth;
//! the value is then deserialized into the typed struct via
//! [`serde_path_to_error`] so errors carry a human-readable YAML path.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::address::IndividualAddress;
use crate::schema::{BussardConfig, Device, Groups, Links};

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
    /// Two device files declare the same individual `address:`. This is a hard
    /// load error (not a silent last-wins collapse): the address is the device
    /// identity, so a duplicate means one device would be dropped and its links
    /// silently misattributed.
    #[error(
        "duplicate device address {address}: declared in both {first} and {second} \
         (each device address must be unique across devices/*.yaml)"
    )]
    DuplicateDeviceAddress {
        /// The colliding individual address.
        address: IndividualAddress,
        /// The first file that declared it (sorted order).
        first: PathBuf,
        /// The second file that declared it.
        second: PathBuf,
    },
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
    /// Serializing a value to YAML failed.
    #[error("serializing {path}: {source}")]
    Yaml {
        /// The target file.
        path: PathBuf,
        /// The underlying error.
        source: serde_norway::Error,
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

/// Parses YAML text into a typed value, rejecting duplicate keys and unknown
/// fields, and attaching the file path plus YAML path to any error.
fn parse_yaml<T: DeserializeOwned>(path: &Path, text: &str) -> Result<T, LoadError> {
    // Stage 1: parse into an untyped value. This rejects duplicate keys at any
    // depth (serde_norway errors when a mapping sees a repeated key).
    let value: serde_norway::Value =
        serde_norway::from_str(text).map_err(|source| LoadError::Yaml {
            path: path.to_path_buf(),
            source,
        })?;

    // Stage 2: deserialize into the typed struct, tracking the YAML path.
    serde_path_to_error::deserialize(value).map_err(|err| {
        let yaml_path = err.path().to_string();
        LoadError::Schema {
            path: path.to_path_buf(),
            yaml_path: if yaml_path.is_empty() {
                ".".to_string()
            } else {
                yaml_path
            },
            message: err.into_inner().to_string(),
        }
    })
}

/// Reads and parses a YAML file into a typed value.
fn load_file<T: DeserializeOwned>(path: &Path) -> Result<T, LoadError> {
    let text = fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_yaml(path, &text)
}

/// Reads and parses an optional YAML file, returning the default if absent.
fn load_optional<T: DeserializeOwned + Default>(path: &Path) -> Result<T, LoadError> {
    if path.exists() {
        load_file(path)
    } else {
        Ok(T::default())
    }
}

/// The fully loaded KNX model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    /// Connection configuration from `bussard.yaml`.
    pub config: BussardConfig,
    /// The group-address plan from `groups.yaml`.
    pub groups: Groups,
    /// The links from `links.yaml`.
    pub links: Links,
    /// Devices from `devices/*.yaml`, keyed by individual address, with the
    /// source filename recorded for diagnostics.
    pub devices: BTreeMap<IndividualAddress, LoadedDevice>,
}

/// A device together with the filename it was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedDevice {
    /// The device definition.
    pub device: Device,
    /// The file stem (filename without extension) it was read from.
    ///
    /// Used by validation to check the `1.1.4-...` naming convention.
    pub file_stem: String,
}

impl Model {
    /// Loads the model from a directory.
    ///
    /// Reads `bussard.yaml` (optional), `groups.yaml`, `links.yaml` and every
    /// `devices/*.yaml`. Two device files declaring the same individual
    /// `address:` are a hard load error ([`LoadError::DuplicateDeviceAddress`],
    /// naming both files): the address is the device identity, and a silent
    /// last-wins collapse would drop a device and misattribute its links. Files
    /// are processed in sorted order for a deterministic "first" file in the
    /// error. The validator's `E002` still flags duplicates that reach a loaded
    /// model by other routes, but the loader no longer produces such a model.
    pub fn load(dir: &Path) -> Result<Self, LoadError> {
        let config: BussardConfig = load_optional(&dir.join("bussard.yaml"))?;
        let groups: Groups = load_optional(&dir.join("groups.yaml"))?;
        let links: Links = load_optional(&dir.join("links.yaml"))?;

        let mut devices = BTreeMap::new();
        let devices_dir = dir.join("devices");
        if devices_dir.is_dir() {
            let mut entries: Vec<PathBuf> = fs::read_dir(&devices_dir)
                .map_err(|source| LoadError::Io {
                    path: devices_dir.clone(),
                    source,
                })?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e == "yaml" || e == "yml")
                })
                .collect();
            entries.sort();

            // Track the source file per address so a duplicate names both files.
            let mut source_file: BTreeMap<IndividualAddress, PathBuf> = BTreeMap::new();
            for path in entries {
                let device: Device = load_file(&path)?;
                let file_stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
                if let Some(first) = source_file.get(&device.address) {
                    return Err(LoadError::DuplicateDeviceAddress {
                        address: device.address,
                        first: first.clone(),
                        second: path,
                    });
                }
                source_file.insert(device.address, path);
                devices.insert(device.address, LoadedDevice { device, file_stem });
            }
        }

        Ok(Self {
            config,
            groups,
            links,
            devices,
        })
    }

    /// Parses a model from in-memory file contents, keyed by model-relative path
    /// (`bussard.yaml`, `groups.yaml`, `links.yaml`, `devices/<stem>.yaml`).
    ///
    /// The in-memory twin of [`Model::load`], used to read a `.bussard` bundle
    /// without extracting it. The same rules hold: every file is optional except
    /// that devices need a `devices/` entry, duplicate keys and unknown fields are
    /// rejected, and two device files declaring one address are an error. Keys
    /// outside those four shapes are ignored.
    pub fn from_texts(files: &BTreeMap<String, String>) -> Result<Self, LoadError> {
        fn optional<T: DeserializeOwned + Default>(
            files: &BTreeMap<String, String>,
            name: &str,
        ) -> Result<T, LoadError> {
            match files.get(name) {
                Some(text) => parse_yaml(Path::new(name), text),
                None => Ok(T::default()),
            }
        }
        let config: BussardConfig = optional(files, "bussard.yaml")?;
        let groups: Groups = optional(files, "groups.yaml")?;
        let links: Links = optional(files, "links.yaml")?;

        let mut devices = BTreeMap::new();
        let mut source_file: BTreeMap<IndividualAddress, PathBuf> = BTreeMap::new();
        for (name, text) in files {
            let Some(file) = name.strip_prefix("devices/") else {
                continue;
            };
            let Some(file_stem) = file
                .strip_suffix(".yaml")
                .or_else(|| file.strip_suffix(".yml"))
                .filter(|stem| !stem.is_empty() && !stem.contains('/'))
            else {
                continue;
            };
            let path = PathBuf::from(name);
            let device: Device = parse_yaml(&path, text)?;
            if let Some(first) = source_file.get(&device.address) {
                return Err(LoadError::DuplicateDeviceAddress {
                    address: device.address,
                    first: first.clone(),
                    second: path,
                });
            }
            source_file.insert(device.address, path);
            devices.insert(
                device.address,
                LoadedDevice {
                    device,
                    file_stem: file_stem.to_string(),
                },
            );
        }

        Ok(Self {
            config,
            groups,
            links,
            devices,
        })
    }

    /// Renders the model to the exact file contents [`Model::save`] would write,
    /// keyed by model-relative path, without touching the disk.
    ///
    /// `bussard.yaml` is always included here (a save skips it only when the
    /// file already exists). Used by `bussard diff --raw` to show a file-level
    /// diff of a side that was never written, such as a `.knxproj`.
    pub fn to_texts(&self) -> Result<BTreeMap<String, String>, SaveError> {
        let mut out = BTreeMap::new();
        out.insert(
            "bussard.yaml".to_string(),
            render_yaml(Path::new("bussard.yaml"), &self.config, BUSSARD_HEADER)?,
        );
        out.insert(
            "groups.yaml".to_string(),
            render_yaml(Path::new("groups.yaml"), &self.groups, GROUPS_HEADER)?,
        );
        out.insert(
            "links.yaml".to_string(),
            render_yaml(Path::new("links.yaml"), &self.links, LINKS_HEADER)?,
        );
        for loaded in self.devices.values() {
            let name = format!("devices/{}.yaml", loaded.file_stem);
            let text = render_device(Path::new(&name), &loaded.device)?;
            out.insert(name, text);
        }
        Ok(out)
    }

    /// Saves the model to a directory with deterministic, sorted output.
    ///
    /// All maps in the schema are `BTreeMap`s keyed by their sorted key type
    /// (GA / IA / object number), so serialization is already deterministic;
    /// each device is written to `devices/<address>-<slug>.yaml`.
    ///
    /// Every file is prefixed with a generated-file banner (issue #16) and the
    /// `com_objects:` block in each device file carries a "regenerated on
    /// re-import" marker; loading tolerates these comments (they are free in
    /// YAML). Stale device files (whose address is no longer in the saved set)
    /// are pruned and reported on stderr (issue #18) — see
    /// [`Model::save_pruning`] for the wrapper the importer uses.
    ///
    /// `bussard.yaml` is *user-owned* — nothing in it derives from the ETS
    /// project — so it is written only when absent and an existing one is left
    /// byte-untouched (issue #28). This preserves the user's gateway/transport
    /// choice across re-imports. (`bussard init` writes its own `bussard.yaml`
    /// directly, so it is unaffected.)
    pub fn save(&self, dir: &Path) -> Result<(), SaveError> {
        fs::create_dir_all(dir).map_err(|source| SaveError::Io {
            path: dir.to_path_buf(),
            source,
        })?;

        let bussard_path = dir.join("bussard.yaml");
        if !bussard_path.exists() {
            write_yaml(&bussard_path, &self.config, BUSSARD_HEADER)?;
        }
        write_yaml(&dir.join("groups.yaml"), &self.groups, GROUPS_HEADER)?;
        write_yaml(&dir.join("links.yaml"), &self.links, LINKS_HEADER)?;

        let devices_dir = dir.join("devices");
        fs::create_dir_all(&devices_dir).map_err(|source| SaveError::Io {
            path: devices_dir.clone(),
            source,
        })?;
        for loaded in self.devices.values() {
            let filename = format!("{}.yaml", loaded.file_stem);
            write_device(&devices_dir.join(filename), &loaded.device)?;
        }
        Ok(())
    }

    /// Saves the model, then prunes device files whose address is not in the
    /// saved set and reports pruned/renamed files on `stderr` (issue #18).
    ///
    /// `address:` is the device identity; the filename slug is cosmetic, so a
    /// renamed device (same address, new name → new slug) writes the new file
    /// and prunes the old one, leaving no duplicate `address:` behind (which
    /// would otherwise be a validation `E002`). Untouched device files are
    /// byte-stable.
    pub fn save_pruning(&self, dir: &Path) -> Result<PruneReport, SaveError> {
        // The device filenames this save produces (the fresh set).
        let kept: BTreeMap<String, ()> = self
            .devices
            .values()
            .map(|l| (format!("{}.yaml", l.file_stem), ()))
            .collect();

        // Existing device files before the save, so we can detect renames.
        let devices_dir = dir.join("devices");
        let existing = list_device_files(&devices_dir);

        self.save(dir)?;

        // Remove any existing device file that the fresh set did not produce.
        // A stale file whose leading `<address>-` prefix still names a device
        // in the model is a *rename* (the new slug file replaced it); anything
        // else is a true prune (the device left the project).
        let mut report = PruneReport::default();
        for name in &existing {
            if kept.contains_key(name) {
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
            eprintln!("renamed device file devices/{old} → devices/{new} (same address, new name)");
        }
        for name in &report.pruned {
            eprintln!("pruned stale device file devices/{name} (device no longer in the project)");
        }
        Ok(report)
    }
}

/// If a stale device filename's `<address>-` prefix matches a device still in
/// the model, returns that device's fresh filename (a rename), else `None`.
fn stale_file_rename_target(
    stale_name: &str,
    devices: &BTreeMap<IndividualAddress, LoadedDevice>,
) -> Option<String> {
    let stem = stale_name.strip_suffix(".yaml")?;
    let addr: IndividualAddress = stem.split('-').next()?.parse().ok()?;
    devices
        .get(&addr)
        .map(|l| format!("{}.yaml", l.file_stem))
        .filter(|new_name| new_name != stale_name)
}

/// The result of a pruning save: which device files were removed or renamed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Device filenames (relative to `devices/`) removed because their device
    /// left the project.
    pub pruned: Vec<String>,
    /// `(old, new)` device filenames replaced because the device kept its
    /// address but changed name (and therefore filename slug).
    pub renamed: Vec<(String, String)>,
}

/// The set of `*.yaml`/`*.yml` filenames currently in a `devices/` directory.
fn list_device_files(devices_dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = match fs::read_dir(devices_dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "yaml" || e == "yml")
            })
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// The banner prefixed to `bussard.yaml`.
const BUSSARD_HEADER: &str = "\
# bussard.yaml — connection config for `bussard`.
#
# Generated by `bussard init`; hand-editable. Sets the transport (tunnel or
# routing), the gateway, the multicast endpoint and, optionally, the KNX
# Secure keyring file (`keyring:`, relative to this directory).
# Docs: https://github.com/tmbo/bussard/blob/main/docs/DESIGN.md#52-the-yaml-model
";

/// Loads only `<dir>/bussard.yaml`, returning the default config when the file
/// is absent. Cheaper than [`Model::load`] for a caller that needs just the
/// connection settings (the CLI's `connection.keyring` default, issue #189).
pub fn load_config(dir: &Path) -> Result<BussardConfig, LoadError> {
    load_optional(&dir.join("bussard.yaml"))
}

/// Loads a `groups.yaml` from an explicit path, returning an empty plan when
/// the file is absent.
///
/// `Model::load` always reads `<dir>/groups.yaml`; the scaffolder needs to read
/// (and extend) whichever file `--out` names, so it goes through here.
pub fn load_groups(path: &Path) -> Result<Groups, LoadError> {
    load_optional(path)
}

/// Writes a `groups.yaml` to an explicit path, with the standard banner.
///
/// Crash-safe like every other model write (staged temp file plus rename).
pub fn save_groups(path: &Path, groups: &Groups) -> Result<(), SaveError> {
    write_yaml(path, groups, GROUPS_HEADER)
}

/// The banner prefixed to `groups.yaml`.
const GROUPS_HEADER: &str = "\
# groups.yaml — the group-address plan (generated by `bussard import`).
#
# Hand-editable: names, DPTs, descriptions and `protected:` flags are yours to
# refine and survive re-import merges where the address is unchanged.
#
# `ranges:` keys name main/middle group ranges: \"3\" is a main group,
# \"3/2\" a middle group. Group addresses are keyed as 3-level strings (\"3/2/0\").
# Docs: https://github.com/tmbo/bussard/blob/main/docs/DESIGN.md#52-the-yaml-model
";

/// The banner prefixed to `links.yaml`.
const LINKS_HEADER: &str = "\
# links.yaml — com-object → group-address assignments (generated by `bussard import`).
#
# This is the single home for the informational com-object `name:` (hand-edit it
# here). Entries are keyed by device address; each references a com-object by its
# ETS `object:` number, with at most one `send:` GA and any number of `listen:` GAs.
# Docs: https://github.com/tmbo/bussard/blob/main/docs/DESIGN.md#52-the-yaml-model
";

/// The banner prefixed to each `devices/*.yaml` file.
const DEVICE_HEADER: &str = "\
# Device file (generated by `bussard import`).
#
# `address:` is the device identity; the filename slug is cosmetic. The identity,
# name, location, product and channel names above `com_objects:` are hand-editable.
#
# `parameters:` holds this device's configured parameter values, keyed
# `<name>@<ref-id>` (only values that differ from the vendor default are stored).
# It is yours to edit, but a re-import REPLACES it with ETS truth — like the
# names in links.yaml, it is imported-but-user-owned, not merged.
# Docs: https://github.com/tmbo/bussard/blob/main/docs/DESIGN.md#52-the-yaml-model
";

/// The marker injected immediately above the `com_objects:` key in device files.
const COM_OBJECTS_MARKER: &str = "\
# --- GENERATED: regenerated on re-import; hand edits here are lost. ---
";

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

/// Serializes a value to a YAML file, prefixed with a generated-file `header`.
///
/// The write is atomic (see [`atomic_write`]): an interrupted save leaves any
/// existing file untouched rather than truncated.
fn write_yaml<T: Serialize>(path: &Path, value: &T, header: &str) -> Result<(), SaveError> {
    let text = render_yaml(path, value, header)?;
    atomic_write(path, text.as_bytes())
}

/// Serializes a value to YAML text prefixed with a generated-file `header`.
fn render_yaml<T: Serialize>(path: &Path, value: &T, header: &str) -> Result<String, SaveError> {
    let body = serde_norway::to_string(value).map_err(|source| SaveError::Yaml {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(format!("{header}{body}"))
}

/// Serializes a [`Device`] to a YAML file, with the device banner and a
/// "regenerated" marker injected immediately above the `com_objects:` key.
///
/// serde_norway emits no comments, so the marker is injected at the string
/// level. The emitter controls the exact output: `com_objects:` is a top-level
/// key, so it appears at column 0 — we match the first line equal to
/// `com_objects:` and insert the marker above it.
fn write_device(path: &Path, device: &Device) -> Result<(), SaveError> {
    let text = render_device(path, device)?;
    atomic_write(path, text.as_bytes())
}

/// Renders a [`Device`] to the text [`write_device`] writes.
fn render_device(path: &Path, device: &Device) -> Result<String, SaveError> {
    let body = serde_norway::to_string(device).map_err(|source| SaveError::Yaml {
        path: path.to_path_buf(),
        source,
    })?;
    let body = inject_com_objects_marker(&body);
    Ok(format!("{DEVICE_HEADER}{body}"))
}

/// Inserts [`COM_OBJECTS_MARKER`] on the line immediately above the **first**
/// generated top-level key in a device file. The generated zone comprises
/// `module_bases:` (emitted first, when non-empty) and `com_objects:`; the marker
/// goes above whichever appears first so the whole generated block sits below it.
/// A no-op when the device has neither key.
fn inject_com_objects_marker(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + COM_OBJECTS_MARKER.len());
    let mut marker_emitted = false;
    for line in body.split_inclusive('\n') {
        // The keys are top-level (column 0), so match the exact line start. Only
        // the first generated key gets the marker; the block below it is contiguous.
        if !marker_emitted && is_generated_key_line(line) {
            out.push_str(COM_OBJECTS_MARKER);
            marker_emitted = true;
        }
        out.push_str(line);
    }
    out
}

/// Whether `line` is a top-level generated device key (`module_bases:` or
/// `com_objects:`) — the boundary above which the GENERATED marker is injected.
fn is_generated_key_line(line: &str) -> bool {
    let trimmed = line.trim_end();
    trimmed == "module_bases:" || trimmed == "com_objects:"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys() {
        let path = Path::new("groups.yaml");
        let yaml = "groups:\n  \"1/0/0\":\n    name: a\n  \"1/0/0\":\n    name: b\n";
        let err = parse_yaml::<Groups>(path, yaml).unwrap_err();
        assert!(matches!(err, LoadError::Yaml { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_unknown_field() {
        let path = Path::new("groups.yaml");
        let yaml = "groups: {}\nbogus: 1\n";
        let err = parse_yaml::<Groups>(path, yaml).unwrap_err();
        assert!(matches!(err, LoadError::Schema { .. }), "got {err:?}");
    }

    #[test]
    fn schema_error_carries_path() {
        let path = Path::new("groups.yaml");
        // dpt must be a string; give it a mapping.
        let yaml = "groups:\n  \"1/0/0\":\n    name: a\n    dpt: {x: 1}\n";
        let err = parse_yaml::<Groups>(path, yaml).unwrap_err();
        if let LoadError::Schema { yaml_path, .. } = err {
            assert!(yaml_path.contains("1/0/0"), "path was {yaml_path}");
        } else {
            panic!("expected schema error, got {err:?}");
        }
    }

    /// Builds a tiny one-device model for the emitted-format tests.
    fn small_model() -> Model {
        use crate::schema::{ComObject, Device, Group, Groups, Link, Links};

        let mut groups = BTreeMap::new();
        groups.insert(
            "3/0/4".parse().unwrap(),
            Group {
                name: "Jalousie Wohnen".to_string(),
                dpt: Some("1.008".parse().unwrap()),
                ..Default::default()
            },
        );

        let mut links = BTreeMap::new();
        links.insert(
            "1.1.4".parse().unwrap(),
            vec![Link {
                object: 12,
                name: Some("A: Behang Auf/Ab".to_string()),
                send: None,
                listen: vec!["3/0/4".parse().unwrap()],
            }],
        );

        let mut com_objects = BTreeMap::new();
        com_objects.insert(
            12u16,
            ComObject {
                dpt: Some("1.008".parse().unwrap()),
                size: None,
                flags: "CW".parse().unwrap(),
                reference: None,
                channel: Some("A".to_string()),
                secure: false,
            },
        );

        let device = Device {
            address: "1.1.4".parse().unwrap(),
            name: "Jalousieaktor Wohnen".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: BTreeMap::new(),
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects,
            security: None,
        };

        let mut devices = BTreeMap::new();
        devices.insert(
            "1.1.4".parse().unwrap(),
            LoadedDevice {
                device,
                file_stem: "1.1.4-jalousieaktor-wohnen".to_string(),
            },
        );

        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links { links },
            devices,
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bussard-loader-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn emitted_files_carry_headers_and_markers() {
        let dir = tmp_dir("golden");
        let model = small_model();
        model.save(&dir).unwrap();

        // groups.yaml: banner present, documents the ranges convention.
        let groups = fs::read_to_string(dir.join("groups.yaml")).unwrap();
        assert!(
            groups.starts_with("# groups.yaml"),
            "groups banner: {groups}"
        );
        assert!(
            groups.contains("\"3\" is a main group"),
            "ranges doc: {groups}"
        );
        assert!(groups.contains("groups:"), "still has body");

        // links.yaml: banner naming it the single home for the name.
        let links = fs::read_to_string(dir.join("links.yaml")).unwrap();
        assert!(links.starts_with("# links.yaml"));
        assert!(links.contains("single home"));

        // Device file: banner + a GENERATED marker directly above com_objects.
        let dev = fs::read_to_string(dir.join("devices/1.1.4-jalousieaktor-wohnen.yaml")).unwrap();
        assert!(dev.starts_with("# Device file"), "device banner: {dev}");
        let marker = "# --- GENERATED: regenerated on re-import; hand edits here are lost. ---\ncom_objects:";
        assert!(dev.contains(marker), "marker above com_objects: {dev}");
        // com_objects entries carry no `name:` and no `size:` (dpt present).
        assert!(
            !dev.contains("name: 'A: Behang"),
            "no com-object name: {dev}"
        );
        assert!(!dev.contains("size:"), "no size when dpt present: {dev}");

        // Golden byte assertion for the device file (small, stable model).
        let expected = "\
# Device file (generated by `bussard import`).
#
# `address:` is the device identity; the filename slug is cosmetic. The identity,
# name, location, product and channel names above `com_objects:` are hand-editable.
#
# `parameters:` holds this device's configured parameter values, keyed
# `<name>@<ref-id>` (only values that differ from the vendor default are stored).
# It is yours to edit, but a re-import REPLACES it with ETS truth — like the
# names in links.yaml, it is imported-but-user-owned, not merged.
# Docs: https://github.com/tmbo/bussard/blob/main/docs/DESIGN.md#52-the-yaml-model
address: 1.1.4
name: Jalousieaktor Wohnen
# --- GENERATED: regenerated on re-import; hand edits here are lost. ---
com_objects:
  12:
    dpt: '1.008'
    flags: CW
    channel: A
";
        assert_eq!(dev, expected, "device golden mismatch");

        // The headers/markers are tolerated on load (round-trips).
        let reloaded = Model::load(&dir).unwrap();
        assert_eq!(model, reloaded);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parameters_emit_above_generated_marker() {
        // A device with a `parameters:` block: it must land in the user-owned
        // zone, above the GENERATED com_objects marker, and round-trip on load.
        use crate::schema::Device;
        let dir = tmp_dir("params");
        let mut model = small_model();
        {
            let loaded = model.devices.get_mut(&"1.1.4".parse().unwrap()).unwrap();
            let dev: &mut Device = &mut loaded.device;
            dev.parameters.insert(
                "windalarm-1@MD-1_M-3_MI-1_P-3_R-45".to_string(),
                "1".to_string(),
            );
            dev.parameters
                .insert("nachtabsenkung@P-1312_R-2140".to_string(), "5".to_string());
        }
        model.save(&dir).unwrap();
        let text = fs::read_to_string(dir.join("devices/1.1.4-jalousieaktor-wohnen.yaml")).unwrap();

        let params_at = text
            .find("\nparameters:\n")
            .expect("parameters block present");
        let marker_at = text.find(COM_OBJECTS_MARKER).expect("marker present");
        assert!(
            params_at < marker_at,
            "parameters: must sit above the GENERATED marker:\n{text}"
        );
        // Keys are BTreeMap-sorted and values are stringy.
        assert!(
            text.contains("  nachtabsenkung@P-1312_R-2140: '5'"),
            "{text}"
        );
        assert!(
            text.contains("  windalarm-1@MD-1_M-3_MI-1_P-3_R-45: '1'"),
            "{text}"
        );

        // Round-trips through load.
        let reloaded = Model::load(&dir).unwrap();
        assert_eq!(model, reloaded);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_bases_emit_inside_generated_zone() {
        // A device with a `module_bases:` block (issue #48): it is generated data,
        // so the GENERATED marker must sit *above* it (and thus above the whole
        // generated block), and it must round-trip byte-idempotently.
        use crate::schema::Device;
        let dir = tmp_dir("module-bases");
        let mut model = small_model();
        {
            let loaded = model.devices.get_mut(&"1.1.4".parse().unwrap()).unwrap();
            let dev: &mut Device = &mut loaded.device;
            dev.module_bases.insert("MD-1_M-1_MI-1".to_string(), 805);
            dev.module_bases.insert("MD-1_M-3_MI-1".to_string(), 1797);
        }
        model.save(&dir).unwrap();
        let text = fs::read_to_string(dir.join("devices/1.1.4-jalousieaktor-wohnen.yaml")).unwrap();

        // The marker precedes module_bases:, which precedes com_objects:.
        let marker_at = text.find(COM_OBJECTS_MARKER).expect("marker present");
        let bases_at = text
            .find("\nmodule_bases:\n")
            .expect("module_bases block present");
        let com_at = text.find("\ncom_objects:\n").expect("com_objects present");
        assert!(
            marker_at < bases_at && bases_at < com_at,
            "GENERATED marker must sit above module_bases (and the whole generated \
             block):\n{text}"
        );
        // Values render as bare integers keyed by the flasher's selector format.
        assert!(text.contains("  MD-1_M-1_MI-1: 805"), "{text}");
        assert!(text.contains("  MD-1_M-3_MI-1: 1797"), "{text}");

        // Byte-idempotent re-save and round-trip through load.
        let reloaded = Model::load(&dir).unwrap();
        assert_eq!(model, reloaded);
        let dir2 = tmp_dir("module-bases-2");
        reloaded.save(&dir2).unwrap();
        let text2 =
            fs::read_to_string(dir2.join("devices/1.1.4-jalousieaktor-wohnen.yaml")).unwrap();
        assert_eq!(text, text2, "re-save is byte-identical");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn save_pruning_removes_stale_and_renamed_files() {
        let dir = tmp_dir("prune");
        let mut model = small_model();
        model.save_pruning(&dir).unwrap();

        // Rename the device (same address, new name → new slug).
        let loaded = model.devices.get_mut(&"1.1.4".parse().unwrap()).unwrap();
        loaded.device.name = "Rollo Wohnen".to_string();
        loaded.file_stem = "1.1.4-rollo-wohnen".to_string();

        let report = model.save_pruning(&dir).unwrap();
        // The old slug file is replaced (a rename, since the address is still
        // present); no duplicate address left behind.
        assert_eq!(
            report.renamed,
            vec![(
                "1.1.4-jalousieaktor-wohnen.yaml".to_string(),
                "1.1.4-rollo-wohnen.yaml".to_string()
            )]
        );
        assert!(report.pruned.is_empty());
        let names = list_device_files(&dir.join("devices"));
        assert_eq!(names, vec!["1.1.4-rollo-wohnen.yaml".to_string()]);

        // Removing the device entirely prunes its file too.
        model.devices.clear();
        let report = model.save_pruning(&dir).unwrap();
        assert_eq!(report.pruned, vec!["1.1.4-rollo-wohnen.yaml"]);
        assert!(report.renamed.is_empty());
        assert!(list_device_files(&dir.join("devices")).is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn untouched_device_files_are_byte_stable() {
        let dir = tmp_dir("stable");
        let model = small_model();
        model.save_pruning(&dir).unwrap();
        let path = dir.join("devices/1.1.4-jalousieaktor-wohnen.yaml");
        let first = fs::read_to_string(&path).unwrap();
        // Re-import the same model: the device file is byte-identical, no prune.
        let report = model.save_pruning(&dir).unwrap();
        assert!(report.pruned.is_empty());
        let second = fs::read_to_string(&path).unwrap();
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_duplicate_device_address_across_files() {
        // Two device files declaring the same `address:` must be a hard load
        // error naming BOTH files — not a silent last-wins collapse.
        let dir = tmp_dir("dup-addr");
        let devices_dir = dir.join("devices");
        fs::create_dir_all(&devices_dir).unwrap();

        let banner_and = |name: &str| {
            format!(
                "address: 1.1.4\nname: {name}\ncom_objects: {{}}\n",
                name = name
            )
        };
        // Sorted order makes "a-..." the first file, "b-..." the second.
        fs::write(devices_dir.join("1.1.4-a-first.yaml"), banner_and("First")).unwrap();
        fs::write(
            devices_dir.join("1.1.4-b-second.yaml"),
            banner_and("Second"),
        )
        .unwrap();

        let err = Model::load(&dir).unwrap_err();
        match err {
            LoadError::DuplicateDeviceAddress {
                address,
                first,
                second,
            } => {
                assert_eq!(address, "1.1.4".parse().unwrap());
                assert!(
                    first.ends_with("1.1.4-a-first.yaml"),
                    "first names the earlier file: {first:?}"
                );
                assert!(
                    second.ends_with("1.1.4-b-second.yaml"),
                    "second names the later file: {second:?}"
                );
            }
            other => panic!("expected DuplicateDeviceAddress, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_creates_bussard_yaml_when_absent() {
        let dir = tmp_dir("bussard-fresh");
        let model = small_model();
        model.save(&dir).unwrap();
        assert!(
            dir.join("bussard.yaml").exists(),
            "fresh save must create bussard.yaml"
        );
        let text = fs::read_to_string(dir.join("bussard.yaml")).unwrap();
        assert!(text.starts_with("# bussard.yaml"), "banner present: {text}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_leaves_existing_bussard_yaml_byte_untouched() {
        // A user-owned bussard.yaml (hand-edited, with a gateway) must survive a
        // re-import byte-for-byte — nothing in it derives from the ETS project
        // (issue #28).
        let dir = tmp_dir("bussard-owned");
        fs::create_dir_all(&dir).unwrap();
        let hand_edited =
            "# my own file\nconnection:\n  transport: tunnel\n  gateway: 10.0.0.9:3671\n";
        fs::write(dir.join("bussard.yaml"), hand_edited).unwrap();

        let model = small_model();
        model.save_pruning(&dir).unwrap();

        let after = fs::read_to_string(dir.join("bussard.yaml")).unwrap();
        assert_eq!(
            after, hand_edited,
            "existing bussard.yaml must be untouched"
        );

        // A second import is still a no-op for it.
        model.save_pruning(&dir).unwrap();
        let after2 = fs::read_to_string(dir.join("bussard.yaml")).unwrap();
        assert_eq!(after2, hand_edited);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_roundtrips() {
        use crate::schema::{Group, Groups};
        use std::collections::BTreeMap;

        // A unique temp directory for this test.
        let dir = std::env::temp_dir().join(format!("bussard-loader-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let mut groups = BTreeMap::new();
        groups.insert(
            "3/0/4".parse().unwrap(),
            Group {
                name: "Auf/Ab".to_string(),
                dpt: Some("1.008".parse().unwrap()),
                description: None,
                ..Default::default()
            },
        );
        let model = Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        };

        model.save(&dir).unwrap();
        let reloaded = Model::load(&dir).unwrap();
        assert_eq!(model.groups, reloaded.groups);

        // Saving twice produces byte-identical output (deterministic).
        let first = fs::read_to_string(dir.join("groups.yaml")).unwrap();
        model.save(&dir).unwrap();
        let second = fs::read_to_string(dir.join("groups.yaml")).unwrap();
        assert_eq!(first, second);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_leaves_no_temp_debris() -> Result<(), Box<dyn std::error::Error>> {
        // A successful save renames its staging file into place, so no `.tmp`
        // files are left behind in the model directory.
        let dir = tmp_dir("atomic-clean");
        small_model().save(&dir)?;

        let stray: Vec<_> = fs::read_dir(&dir)?
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            stray.is_empty(),
            "no temp debris in {dir:?}, found {stray:?}"
        );

        let devices = dir.join("devices");
        let stray_dev: Vec<_> = fs::read_dir(&devices)?
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            stray_dev.is_empty(),
            "no temp debris in devices, found {stray_dev:?}"
        );

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn atomic_write_failure_leaves_original_intact() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate an interrupted/failed save: the staging write fails (its
        // parent directory does not exist), so the helper must report the error
        // WITHOUT having touched the pre-existing committed file.
        let dir = tmp_dir("atomic-intact");
        fs::create_dir_all(&dir)?;
        let target = dir.join("groups.yaml");
        let original = "# committed by the user\ngroups: {}\n";
        fs::write(&target, original)?;

        // A path whose parent directory is missing makes the temp `fs::write`
        // fail, standing in for a crash before the rename step.
        let doomed = dir.join("does-not-exist").join("groups.yaml");
        let err = atomic_write(&doomed, b"new contents that must never appear")
            .expect_err("write into a missing directory must fail");
        assert!(
            matches!(err, SaveError::TempWrite { .. }),
            "expected TempWrite, got {err:?}"
        );

        // The real committed file is byte-for-byte unchanged: never truncated,
        // never partially overwritten.
        let after = fs::read_to_string(&target)?;
        assert_eq!(
            after, original,
            "original config must survive a failed save"
        );

        // And no staging debris leaked into the model directory.
        let stray: Vec<_> = fs::read_dir(&dir)?
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(stray.is_empty(), "failed save left temp debris: {stray:?}");

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn atomic_write_overwrites_completely() -> Result<(), Box<dyn std::error::Error>> {
        // Overwriting a longer existing file with shorter contents must yield
        // exactly the new bytes (no leftover tail from the old file), proving
        // the write goes through a fresh temp file rather than truncate-in-place.
        let dir = tmp_dir("atomic-overwrite");
        fs::create_dir_all(&dir)?;
        let target = dir.join("groups.yaml");
        fs::write(&target, "a".repeat(4096))?;

        atomic_write(&target, b"short")?;
        assert_eq!(fs::read_to_string(&target)?, "short");

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
