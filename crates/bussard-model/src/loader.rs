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
    /// `devices/*.yaml`. Devices with duplicate individual addresses across
    /// files are *not* rejected here — they surface as validation error
    /// `E002` — but the last one loaded wins in the map (files are processed
    /// in sorted order for determinism).
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

            for path in entries {
                let device: Device = load_file(&path)?;
                let file_stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
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

    /// Saves the model to a directory with deterministic, sorted output.
    ///
    /// All maps in the schema are `BTreeMap`s keyed by their sorted key type
    /// (GA / IA / object number), so serialization is already deterministic;
    /// each device is written to `devices/<address>-<slug>.yaml`.
    pub fn save(&self, dir: &Path) -> Result<(), SaveError> {
        fs::create_dir_all(dir).map_err(|source| SaveError::Io {
            path: dir.to_path_buf(),
            source,
        })?;

        write_yaml(&dir.join("bussard.yaml"), &self.config)?;
        write_yaml(&dir.join("groups.yaml"), &self.groups)?;
        write_yaml(&dir.join("links.yaml"), &self.links)?;

        let devices_dir = dir.join("devices");
        fs::create_dir_all(&devices_dir).map_err(|source| SaveError::Io {
            path: devices_dir.clone(),
            source,
        })?;
        for loaded in self.devices.values() {
            let filename = format!("{}.yaml", loaded.file_stem);
            write_yaml(&devices_dir.join(filename), &loaded.device)?;
        }
        Ok(())
    }
}

/// Serializes a value to a YAML file.
fn write_yaml<T: Serialize>(path: &Path, value: &T) -> Result<(), SaveError> {
    let text = serde_norway::to_string(value).map_err(|source| SaveError::Yaml {
        path: path.to_path_buf(),
        source,
    })?;
    fs::write(path, text).map_err(|source| SaveError::Io {
        path: path.to_path_buf(),
        source,
    })
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
}
