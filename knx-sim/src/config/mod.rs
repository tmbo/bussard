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
/// conformance-tested against either realisation. Default: property-based (the
/// M2 Jung 0705 capture, issue #70, showed the real device drives load control
/// over `PID_LOAD_STATE_CONTROL`).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LsmAccessConfig {
    /// 12-octet record over `A_Memory_Write` to the LSM control address, status
    /// polled via `A_Memory_Read`. The pre-M2 default, kept selectable for any
    /// 0705 silicon whose product data drives the LSM this way.
    Memory,
    /// Load events over `PID_LOAD_STATE_CONTROL` (PID 5) via
    /// `A_PropertyValue_Write/Read` (the default — M2 Jung 0705 capture).
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
    LsmAccessConfig::Property
}

/// Per-device KNX Data Secure configuration (spec §12.2). A device with a
/// `security:` block is treated as security-ACTIVATED: all management access
/// must ride A_SecureData, and a plain access to a protected function is refused.
/// Omitting the block leaves the device plain (the default), so existing configs
/// and devices are unaffected.
///
/// All key material is SYNTHETIC and lives only in this config; it is never read
/// from a user's real key files. The `tool_key` is 32 hex characters (16 raw
/// bytes).
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// The activation flag. Must be `activated` to secure the device; any other
    /// value (or omitting the whole block) leaves it plain.
    pub status: SecurityStatus,
    /// The synthetic tool key as 32 hex characters (16 bytes). Required when
    /// `status: activated`.
    pub tool_key: String,
    /// The device's initial send sequence (spec §5.8), for wrapping responses.
    /// Defaults to 0.
    #[serde(default)]
    pub initial_tx_seq: u64,
    /// The device's initial receive-freshness floor (spec §5.9): a first inbound
    /// frame must strictly exceed this. Defaults to 0.
    #[serde(default)]
    pub initial_rx_seq: u64,
}

/// The activation status of a device's KNX Data Secure block.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityStatus {
    /// The device is security-activated: management access must be secured.
    Activated,
    /// The device is plain (the default when the block is omitted).
    Plain,
}

impl SecurityConfig {
    /// Convert to the device-layer activation, parsing the synthetic tool key.
    /// Returns a plain (`None`) activation only when `status: plain`; an
    /// `activated` block with a bad key is an error.
    fn to_activation(&self) -> Result<crate::device::SecureActivation, String> {
        if self.status != SecurityStatus::Activated {
            return Err("security block present but status is not `activated`".into());
        }
        let tool_key = crate::secure::Key16::from_hex(&self.tool_key)
            .ok_or_else(|| "tool_key must be 32 hex characters (16 bytes)".to_string())?;
        Ok(crate::device::SecureActivation {
            tool_key,
            initial_tx_seq: self.initial_tx_seq,
            initial_rx_seq: self.initial_rx_seq,
        })
    }
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
    /// wire (default: property-based, the M2 Jung 0705 capture). Ignored for
    /// System B.
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
    /// Whether the device starts in KNX programming mode (default `false`). A
    /// device in programming mode answers the broadcast `A_IndividualAddress_Read`
    /// — the discovery step `bussard assign` and `bussard viz --watch-prog` use.
    /// The `KNX_SIM_PROG_MODE` environment variable (a comma-separated list of
    /// individual addresses) forces this on for the listed devices, so a human can
    /// start a running sim with a device already in programming mode without
    /// editing the config.
    #[serde(default)]
    pub prog_mode: bool,
    /// KNX Data Secure activation (spec §12.2). Omit to keep the device plain
    /// (the default). A `security: { status: activated, tool_key: <32 hex> }`
    /// block marks the device security-activated with a SYNTHETIC tool key.
    #[serde(default)]
    pub security: Option<SecurityConfig>,
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

/// Environment variable that forces programming mode on for specific devices.
///
/// A comma-separated list of individual addresses (e.g. `1.1.2,1.1.5`). Any
/// device whose address is listed starts in programming mode regardless of its
/// config `prog_mode` value — a convenient way to bring a running sim's device
/// into programming mode for `bussard assign` / `bussard viz --watch-prog`
/// without editing the config. Unset (the default) leaves each device's config
/// value in force.
const PROG_MODE_ENV: &str = "KNX_SIM_PROG_MODE";

/// The effective initial programming-mode flag for a device: `true` when the
/// [`PROG_MODE_ENV`] list names this `address`, else the device's config value.
fn effective_prog_mode(address: &str, config_value: bool) -> bool {
    match std::env::var(PROG_MODE_ENV) {
        Ok(list) => {
            config_value
                || list
                    .split(',')
                    .map(str::trim)
                    .any(|entry| !entry.is_empty() && entry == address.trim())
        }
        Err(_) => config_value,
    }
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
    /// Unused (and may be omitted) when `values` is empty.
    #[serde(default)]
    pub dpt: String,
    /// The values to cycle through, each parsed per `dpt` (e.g. `"1"`/`"0"` for
    /// DPT 1.001, `"21.5"` for DPT 9.001). Empty or omitted: the device
    /// re-transmits the object's current value on every fire, whatever wrote it
    /// (any DPT; a never-written object sends 0).
    #[serde(default)]
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
            // Only an `activated` security block produces a session; a `plain`
            // block (or an absent one) leaves the device plain (spec §6.4).
            let secure = match &dc.security {
                Some(sec) if sec.status == SecurityStatus::Activated => Some(
                    sec.to_activation()
                        .map_err(|reason| ConfigError::BadDeviceOption {
                            device: dc.address.clone(),
                            reason,
                        })?,
                ),
                _ => None,
            };
            let overrides = crate::device::ProfileOverrides {
                mask: dc.mask.clone(),
                lsm_access: dc.lsm_access.into(),
                bcu_key,
                prog_mode: effective_prog_mode(&dc.address, dc.prog_mode),
                secure,
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
    fn test_parse_config_prog_mode() -> Result<(), ConfigError> {
        // A device may declare `prog_mode: true` to start in programming mode;
        // omitting it defaults to false.
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices:
  - address: "1.1.2"
    knxprod: "x.knxprod"
    prog_mode: true
  - address: "1.1.3"
    knxprod: "y.knxprod"
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        assert!(cfg.devices[0].prog_mode, "explicit prog_mode: true parses");
        assert!(!cfg.devices[1].prog_mode, "prog_mode defaults to false");
        Ok(())
    }

    #[test]
    fn test_effective_prog_mode_config_value() {
        // With the env unset (nextest runs each test in its own process, so this
        // is deterministic), the config value is used verbatim.
        assert!(super::effective_prog_mode("1.1.2", true));
        assert!(!super::effective_prog_mode("1.1.2", false));
    }

    #[test]
    fn test_parse_config_system7_options() -> Result<(), ConfigError> {
        // A System 7 device may declare a mask override, an lsm_access mode and a
        // bcu_key. lsm_access defaults to `property` (M2 Jung 0705 capture); the
        // memory-mapped variant stays selectable via `lsm_access: memory`.
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices:
  - address: "1.1.5"
    knxprod: "x.knxprod"
    mask: "0705"
    lsm_access: memory
    bcu_key: "0x12345678"
  - address: "1.1.6"
    knxprod: "y.knxprod"
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        assert_eq!(cfg.devices[0].mask.as_deref(), Some("0705"));
        // The memory-mapped variant is still selectable.
        assert_eq!(cfg.devices[0].lsm_access, LsmAccessConfig::Memory);
        assert_eq!(cfg.devices[0].bcu_key.as_deref(), Some("0x12345678"));
        // Defaults on the second device: no mask, property-based LSM, no key.
        assert_eq!(cfg.devices[1].mask, None);
        assert_eq!(cfg.devices[1].lsm_access, LsmAccessConfig::Property);
        assert_eq!(cfg.devices[1].bcu_key, None);
        Ok(())
    }

    #[test]
    fn test_build_stimulus_without_values_repeats_current() -> Result<(), ConfigError> {
        // A stimulus with no `values` (and no `dpt`) is kept: the device
        // re-transmits the object's current value (the secured-group example).
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices: []
stimulus:
  - device: "1.1.10"
    object: 1
    period_ms: 5000
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        let jobs = cfg.build_stimulus()?;
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].values.is_empty());
        assert_eq!(jobs[0].period_ms, 5000);
        assert_eq!(jobs[0].next_due_ms, 2500);
        Ok(())
    }

    #[test]
    fn test_parse_config_security_activated() -> Result<(), ConfigError> {
        // A device may declare a KNX Data Secure activation block with a synthetic
        // tool key and starting sequences. Omitting it leaves the device plain.
        let yaml = r#"
gateway:
  host: "127.0.0.1"
  port: 3671
devices:
  - address: "1.1.2"
    knxprod: "x.knxprod"
    security:
      status: activated
      tool_key: "0102030405060708090a0b0c0d0e0f10"
      initial_tx_seq: 200
      initial_rx_seq: 1000
  - address: "1.1.3"
    knxprod: "y.knxprod"
"#;
        let cfg = SimConfig::from_yaml(yaml)?;
        let sec = cfg.devices[0].security.as_ref().expect("security parses");
        assert_eq!(sec.status, SecurityStatus::Activated);
        assert_eq!(sec.tool_key, "0102030405060708090a0b0c0d0e0f10");
        assert_eq!(sec.initial_tx_seq, 200);
        assert_eq!(sec.initial_rx_seq, 1000);
        // The synthetic key parses into a valid activation.
        assert!(sec.to_activation().is_ok());
        // The second device has no security block (plain, the default).
        assert!(cfg.devices[1].security.is_none());
        Ok(())
    }

    #[test]
    fn test_security_bad_tool_key_rejected() {
        let sec = SecurityConfig {
            status: SecurityStatus::Activated,
            tool_key: "not-hex".into(),
            initial_tx_seq: 0,
            initial_rx_seq: 0,
        };
        assert!(sec.to_activation().is_err(), "a bad tool key is rejected");
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
