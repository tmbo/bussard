//! TEMPORARY: reads the retired YAML model so the one-off converter
//! (`examples/convert_yaml_model.rs`) can turn fixtures into TOML.
//!
//! Deleted together with the converter once the fixtures are converted.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::address::IndividualAddress;
use crate::loader::{LoadedDevice, Model};
use crate::schema::{BussardConfig, Device, Groups, Links};

/// Reads and parses one optional YAML file.
fn optional<T: DeserializeOwned + Default>(path: &Path) -> Result<T, String> {
    if !path.exists() {
        return Ok(T::default());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_norway::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Loads a YAML model directory (`bussard.yaml`, `groups.yaml`, `links.yaml`,
/// `devices/*.yaml`) into the in-memory [`Model`].
pub fn load(dir: &Path) -> Result<Model, String> {
    let config: BussardConfig = optional(&dir.join("bussard.yaml"))?;
    let groups: Groups = optional(&dir.join("groups.yaml"))?;
    let links: Links = optional(&dir.join("links.yaml"))?;
    let mut devices: BTreeMap<IndividualAddress, LoadedDevice> = BTreeMap::new();
    let devices_dir = dir.join("devices");
    if devices_dir.is_dir() {
        let mut entries: Vec<PathBuf> = fs::read_dir(&devices_dir)
            .map_err(|e| format!("{}: {e}", devices_dir.display()))?
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
            let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let device: Device =
                serde_norway::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            if devices.contains_key(&device.address) {
                return Err(format!("duplicate device address {}", device.address));
            }
            devices.insert(
                device.address,
                LoadedDevice {
                    file_stem: device.address.to_string(),
                    device,
                },
            );
        }
    }
    Ok(Model {
        config,
        groups,
        links,
        devices,
    })
}
