//! File-driven configuration of a virtual installation.
//!
//! A YAML config declares the tunnelling gateway endpoint and the devices on
//! the bus. Loading it reads each device's `.knxprod` and builds a [`Bus`] with
//! one [`Device`] per entry.
//!
//! ```yaml
//! gateway:
//!   host: "127.0.0.1"
//!   port: 3671
//! devices:
//!   - address: "1.1.2"
//!     knxprod: "tests/fixtures/KNX_Virtual_M-00FA.knxprod"
//!     application: "M-00FA_A-2500-10-51CB"
//!     initial_state: "unloaded"
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

use crate::bus::event::EventSink;
use crate::bus::{Bus, StimulusJob};
use crate::device::{Device, LoadState};
use crate::prod::read_knxprod;
use crate::wire::IndividualAddress;

/// The gateway (KNXnet/IP tunnelling endpoint) the simulator listens on.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Bind host (e.g. `127.0.0.1`).
    pub host: String,
    /// Bind UDP port (e.g. `3671`).
    pub port: u16,
}

/// The initial load state of a device's objects, as declared in config.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InitialState {
    /// Objects start Unloaded (a bare device awaiting a flash).
    Unloaded,
    /// Objects start Loaded (a previously-programmed device).
    Loaded,
}

impl From<InitialState> for LoadState {
    fn from(s: InitialState) -> Self {
        match s {
            InitialState::Unloaded => LoadState::Unloaded,
            InitialState::Loaded => LoadState::Loaded,
        }
    }
}

/// How a System 7 device realises its load-state machines, as declared in
/// config. Selects the device side the simulator presents so a tool can be
/// conformance-tested against either realisation. Default: memory-mapped.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LsmAccessConfig {
    /// 12-octet record over `A_Memory_Write` to the LSM control address, status
    /// polled via `A_Memory_Read` (the default).
    Memory,
    /// Load events over `PID_LOAD_STATE_CONTROL` (PID 5) via
    /// `A_PropertyValue_Write/Read`.
    Property,
}

impl From<LsmAccessConfig> for crate::device::LsmAccess {
    fn from(c: LsmAccessConfig) -> Self {
        match c {
            LsmAccessConfig::Memory => crate::device::LsmAccess::MemoryMapped,
            LsmAccessConfig::Property => crate::device::LsmAccess::Property,
        }
    }
}

fn default_lsm_access() -> LsmAccessConfig {
    LsmAccessConfig::Memory
}

/// One device entry in the config.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceConfig {
    /// The device's individual address (e.g. `1.1.2`).
    pub address: String,
    /// Path to the device's `.knxprod` product file.
    pub knxprod: PathBuf,
    /// The application-program id to select from the product (optional; the
    /// first is used if omitted).
    #[serde(default)]
    pub application: Option<String>,
    /// The initial load state (default: unloaded).
    #[serde(default = "default_initial_state")]
    pub initial_state: InitialState,
    /// Override the device's mask (e.g. `"0705"`, `"MV-07B0"`). When omitted the
    /// mask comes from the product's `MaskVersion`. Selects the System B vs
    /// System 7 device model.
    #[serde(default)]
    pub mask: Option<String>,
    /// For a System 7 device, how its load-state machines are realised on the
    /// wire (default: memory-mapped). Ignored for System B.
    #[serde(default = "default_lsm_access")]
    pub lsm_access: LsmAccessConfig,
    /// For a System 7 device, the BCU key (as a hex or decimal `u32`) required
    /// for memory access. Omit for free access (the default): any key unlocks.
    /// When set, memory/load writes before a successful `A_Authorize` with the
    /// matching key are refused.
    #[serde(default)]
    pub bcu_key: Option<String>,
    /// The device's per-connection numbered-exchange budget: after this many
    /// accepted NDTs on one L4 connection the device drops the connection,
    /// modelling a real connection-oriented device's per-connection resource
    /// limit (KNX Virtual drops at ~35). Omit (or set to null) for unlimited (the
    /// default), so existing configs are unaffected. Set it low (e.g. 25) to
    /// reproduce the drop and exercise a tool's periodic-reconnect strategy. The
    /// `KNX_SIM_L4_BUDGET` environment variable overrides this for every device.
    #[serde(default)]
    pub l4_exchange_budget: Option<u32>,
}

fn default_initial_state() -> InitialState {
    InitialState::Unloaded
}

/// Environment variable that overrides every device's `l4_exchange_budget`.
///
/// When set to a parseable `u32`, every device on the bus uses that budget,
/// regardless of the per-device config value — a convenient way to reproduce the
/// connection drop against an existing config without editing it. An unset or
/// unparseable value leaves each device's config value in force.
const L4_BUDGET_ENV: &str = "KNX_SIM_L4_BUDGET";

/// The effective per-connection exchange budget for a device: the
/// [`L4_BUDGET_ENV`] override when set and parseable, else the device's config
/// value.
fn effective_l4_budget(config_value: Option<u32>) -> Option<u32> {
    std::env::var(L4_BUDGET_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .or(config_value)
}

/// One scripted stimulus entry: a device periodically transmits a value on one
/// of its com-objects, so an observed bus is alive without any external writes.
///
/// The value is encoded to KNX bytes for the given `dpt` (a small,
/// deterministic codec covering the DPTs the example uses: 1.001 and 9.001) and
/// sent as an `A_GroupValue_Write` from the device's **send** group address for
/// `object` — resolved from the device's own flashed association table, so a
/// stimulus only fires once the device is `Loaded` and actually linked. The
/// device cycles through `values` in order, wrapping around.
#[derive(Debug, Clone, Deserialize)]
pub struct StimulusConfig {
    /// The individual address of the transmitting device (e.g. `1.0.3`).
    pub device: String,
    /// The com-object number that transmits (must have a send GA in the flashed
    /// association table).
    pub object: u16,
    /// The transmit period in milliseconds.
    pub period_ms: u64,
    /// The datapoint type used to encode the values (e.g. `1.001`, `9.001`).
    pub dpt: String,
    /// The values to cycle through, each parsed per `dpt` (e.g. `"1"`/`"0"` for
    /// DPT 1.001, `"21.5"` for DPT 9.001).
    pub values: Vec<String>,
}

/// The whole installation config.
#[derive(Debug, Clone, Deserialize)]
pub struct SimConfig {
    /// The gateway endpoint.
    pub gateway: GatewayConfig,
    /// The devices on the bus.
    pub devices: Vec<DeviceConfig>,
    /// Optional scripted stimulus: periodic device transmits that keep the bus
    /// alive for observation. Empty (the default) means a quiet bus.
    #[serde(default)]
    pub stimulus: Vec<StimulusConfig>,
}

/// Errors from loading a config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// I/O error reading the config or a product file.
    #[error("io error reading {path}: {source}")]
    Io {
        /// The path involved.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The YAML did not parse.
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_norway::Error),
    /// A device address string was invalid.
    #[error("bad device address {addr:?}: {reason}")]
    BadAddress {
        /// The offending address.
        addr: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A product file failed to read.
    #[error("product error for {path}: {source}")]
    Product {
        /// The product path.
        path: String,
        /// The underlying error.
        source: crate::prod::ProdError,
    },
    /// A stimulus entry could not be prepared (bad value or unsupported DPT).
    #[error("stimulus error for device {device}: {source}")]
    Stimulus {
        /// The stimulus device address.
        device: String,
        /// The underlying encoding error.
        source: crate::wire::dpt::DptError,
    },
    /// A device option (mask override, bcu_key, unmodelled mask) was invalid.
    #[error("device {device}: {reason}")]
    BadDeviceOption {
        /// The device address.
        device: String,
        /// Why the option was rejected.
        reason: String,
    },
}

/// Parse a `bcu_key` config string (hex `0x...` or decimal) into a `u32`.
fn parse_bcu_key(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

impl SimConfig {
    /// Parse a config from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        Ok(serde_norway::from_str(yaml)?)
    }

    /// Load a config from a YAML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::from_yaml(&text)
    }

    /// Build a [`Bus`] from this config, resolving product files relative to
    /// `base_dir` (typically the config file's directory).
    pub fn build_bus(
        &self,
        base_dir: &Path,
        events: Arc<dyn EventSink>,
    ) -> Result<Bus, ConfigError> {
        let mut bus = Bus::new(events.clone());
        for dc in &self.devices {
            let address: IndividualAddress =
                dc.address
                    .parse()
                    .map_err(|reason| ConfigError::BadAddress {
                        addr: dc.address.clone(),
                        reason,
                    })?;
            let prod_path = if dc.knxprod.is_absolute() {
                dc.knxprod.clone()
            } else {
                base_dir.join(&dc.knxprod)
            };
            let product =
                read_knxprod(&prod_path, dc.application.as_deref()).map_err(|source| {
                    ConfigError::Product {
                        path: prod_path.display().to_string(),
                        source,
                    }
                })?;
            let bcu_key = match &dc.bcu_key {
                Some(s) => Some(
                    parse_bcu_key(s).ok_or_else(|| ConfigError::BadDeviceOption {
                        device: dc.address.clone(),
                        reason: format!(
                            "bad bcu_key {s:?}: expected a u32 (hex `0x..` or decimal)"
                        ),
                    })?,
                ),
                None => None,
            };
            let overrides = crate::device::ProfileOverrides {
                mask: dc.mask.clone(),
                lsm_access: dc.lsm_access.into(),
                bcu_key,
            };
            let device = Device::from_product_with_overrides(
                address,
                &product,
                dc.initial_state.into(),
                overrides,
                events.clone(),
            )
            .map_err(|reason| ConfigError::BadDeviceOption {
                device: dc.address.clone(),
                reason,
            })?
            .with_l4_exchange_budget(effective_l4_budget(dc.l4_exchange_budget));
            bus.add_device(device);
        }
        bus.set_stimulus(self.build_stimulus()?);
        Ok(bus)
    }

    /// Prepare the scripted stimulus jobs, encoding each declared value to
    /// group-data octets for its DPT. The first fire of every job is staggered by
    /// half a period so several devices do not all transmit on the same tick.
    fn build_stimulus(&self) -> Result<Vec<StimulusJob>, ConfigError> {
        let mut jobs = Vec::new();
        for (i, s) in self.stimulus.iter().enumerate() {
            let device: IndividualAddress =
                s.device.parse().map_err(|reason| ConfigError::BadAddress {
                    addr: s.device.clone(),
                    reason,
                })?;
            let mut values = Vec::with_capacity(s.values.len());
            for v in &s.values {
                let bytes = crate::wire::dpt::encode(&s.dpt, v).map_err(|source| {
                    ConfigError::Stimulus {
                        device: s.device.clone(),
                        source,
                    }
                })?;
                values.push(bytes);
            }
            if values.is_empty() {
                continue;
            }
            let period_ms = s.period_ms as u128;
            // Stagger the first fire so concurrent stimuli interleave on the bus.
            let next_due_ms = (period_ms / 2) + (i as u128 * 250);
            jobs.push(StimulusJob {
                device,
                object: s.object,
                period_ms,
                values,
                next_due_ms,
                cursor: 0,
            });
        }
        Ok(jobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::event::RecordingSink;

    #[test]
    fn test_parse_config() -> Result<(), ConfigError> {
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices:
  - address: "1.1.2"
    knxprod: "tests/fixtures/KNX_Virtual_M-00FA.knxprod"
    application: "M-00FA_A-2500-10-51CB"
    initial_state: unloaded
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        assert_eq!(cfg.gateway.port, 3671);
        assert_eq!(cfg.devices.len(), 1);
        assert_eq!(cfg.devices[0].initial_state, InitialState::Unloaded);
        // Absent by default (unlimited exchange budget).
        assert_eq!(cfg.devices[0].l4_exchange_budget, None);
        Ok(())
    }

    #[test]
    fn test_parse_config_l4_exchange_budget() -> Result<(), ConfigError> {
        // A device may declare a per-connection numbered-exchange budget; it parses
        // into `l4_exchange_budget`. Omitting it leaves it `None` (unlimited).
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices:
  - address: "1.1.2"
    knxprod: "x.knxprod"
    l4_exchange_budget: 25
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        assert_eq!(cfg.devices[0].l4_exchange_budget, Some(25));
        Ok(())
    }

    #[test]
    fn test_parse_config_system7_options() -> Result<(), ConfigError> {
        // A System 7 device may declare a mask override, an lsm_access mode and a
        // bcu_key. lsm_access defaults to `memory`.
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices:
  - address: "1.1.5"
    knxprod: "x.knxprod"
    mask: "0705"
    lsm_access: property
    bcu_key: "0x12345678"
  - address: "1.1.6"
    knxprod: "y.knxprod"
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        assert_eq!(cfg.devices[0].mask.as_deref(), Some("0705"));
        assert_eq!(cfg.devices[0].lsm_access, LsmAccessConfig::Property);
        assert_eq!(cfg.devices[0].bcu_key.as_deref(), Some("0x12345678"));
        // Defaults on the second device: no mask, memory-mapped LSM, no key.
        assert_eq!(cfg.devices[1].mask, None);
        assert_eq!(cfg.devices[1].lsm_access, LsmAccessConfig::Memory);
        assert_eq!(cfg.devices[1].bcu_key, None);
        Ok(())
    }

    #[test]
    fn test_parse_bcu_key_hex_and_decimal() {
        assert_eq!(parse_bcu_key("0x12345678"), Some(0x1234_5678));
        assert_eq!(parse_bcu_key("305419896"), Some(0x1234_5678));
        assert_eq!(parse_bcu_key("0xFFFFFFFF"), Some(0xFFFF_FFFF));
        assert_eq!(parse_bcu_key("not-a-key"), None);
    }

    #[test]
    fn test_build_bus_from_config() -> Result<(), ConfigError> {
        if crate::testfixtures::da_tp_knxprod().is_none() {
            eprintln!("SKIP: DA.tp fixture not present");
            return Ok(());
        }
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices:
  - address: "1.1.2"
    knxprod: "KNX_Virtual_M-00FA.knxprod"
    application: "M-00FA_A-2500-10-51CB"
    initial_state: loaded
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let sink = Arc::new(RecordingSink::new());
        let bus = cfg.build_bus(&base, sink)?;
        assert_eq!(bus.device_count(), 1);
        Ok(())
    }
}
