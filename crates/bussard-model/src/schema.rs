//! The on-disk YAML schema for a bussard KNX-as-code repository.
//!
//! These structs mirror the files described in the design document (§5.2):
//! `bussard.yaml`, `groups.yaml`, `links.yaml` and `devices/*.yaml`. All use
//! `deny_unknown_fields` so typos are rejected rather than silently ignored.
//!
//! Serialization is isolated in the [`crate::loader`] module; these types just
//! define the shape.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::address::{GroupAddress, IndividualAddress};
use crate::dpt::Dpt;
use crate::flags::Flags;
use crate::lint::LintConfig;

/// The default routing multicast endpoint (`224.0.23.12:3671`).
pub const DEFAULT_MULTICAST: &str = "224.0.23.12:3671";

/// The transport used to reach the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// KNXnet/IP tunneling (unicast to a gateway).
    Tunnel,
    /// KNXnet/IP routing (multicast).
    Routing,
}

/// Connection configuration (`bussard.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BussardConfig {
    /// Connection settings.
    #[serde(default)]
    pub connection: Connection,
    /// Opt-in topology and convention lint rules (issue #102). Absent means the
    /// `L0xx` lints do not run, so an existing model gains no new warnings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lint: Option<LintConfig>,
}

/// The `connection` block of `bussard.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    /// Transport to use.
    pub transport: Transport,
    /// Gateway `host:port` for tunneling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Multicast `addr:port` for routing (default `224.0.23.12:3671`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multicast: Option<String>,
    /// The ETS `.knxkeys` keyring every bus command uses when `--keyring` is
    /// not given (issue #189). A relative path is resolved against the model
    /// directory (the directory holding `bussard.yaml`). The password still
    /// comes from `BUSSARD_KEYRING_PASSWORD`; the file never lives in the
    /// committed model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring: Option<std::path::PathBuf>,
}

impl Connection {
    /// The configured keyring path, resolved against the model directory
    /// `dir` when relative, or `None` when `connection.keyring` is unset.
    pub fn keyring_path(&self, dir: &std::path::Path) -> Option<std::path::PathBuf> {
        self.keyring.as_ref().map(|path| {
            if path.is_absolute() {
                path.clone()
            } else {
                dir.join(path)
            }
        })
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            transport: Transport::Tunnel,
            gateway: None,
            multicast: None,
            keyring: None,
        }
    }
}

/// The group-address plan (`groups.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Groups {
    /// Optional project name metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Optional provenance metadata (e.g. source `.knxproj`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_from: Option<String>,
    /// Named main/middle ranges, keyed by `"3"` or `"3/2"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ranges: BTreeMap<String, Range>,
    /// The group addresses, keyed by GA.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<GroupAddress, Group>,
}

/// A named GA range (main or main/middle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    /// Display name for the range.
    pub name: String,
}

/// A single group address definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Display name.
    pub name: String,
    /// Datapoint type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpt: Option<Dpt>,
    /// Free-text description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this GA is safety-critical and guarded against casual writes.
    ///
    /// When `true`, the CLI refuses to write to it without `--force` and the MCP
    /// server refuses outright (there is no MCP override). Used for objects like
    /// a wind alarm or central functions (see the design document §8). Serialized
    /// only when `true`, so unprotected GAs stay diff-clean.
    #[serde(default, skip_serializing_if = "is_false")]
    pub protected: bool,
    /// Whether ETS runs this group address with KNX Data Secure group
    /// communication (issue #156). Imported from the project: the GA carries a
    /// group key there (or `Security="On"`). The key itself lives only in the
    /// `.knxkeys` keyring, never here. A secured GA's telegrams are encrypted,
    /// and `flash --keyring` / `apply --keyring` program its group key and the
    /// security flags of the group objects linked to it. Serialized only when
    /// `true`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub secure: bool,
}

/// Serde helper: skip a `bool` field when it is `false`.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Com-object → GA assignments (`links.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Links {
    /// Links keyed by device individual address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<IndividualAddress, Vec<Link>>,
}

/// A single com-object link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    /// The ETS com-object number (the stable handle).
    pub object: u16,
    /// Informational name (refreshed on import).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The single sending GA, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<GroupAddress>,
    /// The listening GAs (may be empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listen: Vec<GroupAddress>,
}

/// A device definition (`devices/*.yaml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// The device's individual address.
    pub address: IndividualAddress,
    /// Display name.
    pub name: String,
    /// Free-text description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Physical location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// When this device was last replaced by `bussard replace`, as an RFC3339
    /// UTC date-time (issue #98).
    ///
    /// A replacement swaps the physical hardware behind an individual address.
    /// Nothing else in the model changes, so without this field the history of a
    /// device that died and was swapped is invisible. Absent on every device that
    /// was never replaced, and skipped on serialization, so existing device files
    /// round-trip byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced: Option<String>,
    /// Product identity (for matching `.knxprod` in later phases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,
    /// Named channels.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub channels: BTreeMap<String, Channel>,
    /// Per-device parameter values, keyed by a stable parameter **key** (see the
    /// key-scheme note below), each mapped to its configured value string.
    ///
    /// This block sits in the hand-editable zone *above* the generated
    /// `com_objects:` marker: it is user-owned like `links.yaml` names, but a
    /// re-import **replaces** it wholesale with ETS truth (the emitted device
    /// banner says so). Only values that differ from the vendor default are
    /// stored, so the block is diff-friendly and small.
    ///
    /// # The key scheme (why it looks like this)
    ///
    /// A device's parameters come from its ETS `ParameterInstanceRef`s, each of
    /// which carries a `Value` and a `RefId` pointing at an application-program
    /// `ParameterRef`. The obvious human key — the parameter *Name* — is **not
    /// unique**, for two independent reasons found in real data
    /// (`home_test.knxproj`, the Jung 23024 with 2932 parameters):
    ///
    /// 1. **Module-instance repetition.** A channel module's memory-bearing
    ///    parameter (e.g. the blind actuator's `_xJA_A12_Windalarm_1`,
    ///    app-relative `MD-1_P-3`) is instantiated once per channel: it appears
    ///    under 12 distinct module-instance selectors (`MD-1_M-1_MI-1` …
    ///    `MD-1_M-13_MI-1`), each with its own memory offset and its own value.
    ///    The Name alone collapses all twelve into one.
    /// 2. **Multi-ref parameters.** A single parameter def can have many
    ///    `ParameterRef`s with distinct values inside one instance (e.g. the
    ///    display label `_RE_Bezeichnung`/`MD-2_P-15` had 12 refs `R-17`, `R-712`
    ///    … each naming a different room). Only the `ParameterRef` id
    ///    distinguishes them.
    ///
    /// The one handle that is unique-per-device *and* stable across re-imports is
    /// therefore the **app-relative `ParameterRef` id, with the module-instance
    /// selector preserved** — verified unique within every device block in the
    /// real project (0 collisions across 1053 valued refs). To keep the key
    /// human-scannable we prefix a slug of the parameter Name:
    ///
    /// ```text
    /// <name-slug>@<app-relative-ref-id>
    /// ```
    ///
    /// e.g. `windalarm-1@MD-1_M-3_MI-1_P-3_R-45` (a per-channel module parameter)
    /// or `nachtabsenkung@P-1312_R-2140` (a plain parameter). The part after `@`
    /// is the load-bearing, ETS-stable identity; the slug before it is a
    /// human aid and is ignored when resolving. Stripping the `_M-<m>_MI-<n>`
    /// selector and the `_R-<r>` suffix yields the application `Parameter` id
    /// (`MD-1_P-3` / `P-1312`), which keys `models/<application_ref>.yaml` — so
    /// both the flasher and the validator can resolve a key to its definition.
    ///
    /// Display-only parameters (no `<Memory>`) and `<Union>` members are stored
    /// like any other: a display-only parameter decides through the Dynamic
    /// section which modules, com-objects and parameters the device carries, and
    /// a union member is written at the union's location (issue #123).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, String>,
    /// Per-module-instance memory **base offsets**, keyed by the module-instance
    /// selector (`MD-<d>_M-<m>_MI-<n>`) and mapping to the byte the instance's
    /// module parameters are placed *relative to*.
    ///
    /// This is a **generated** table, sitting in the regenerated zone below the
    /// GENERATED marker alongside `com_objects:` (a re-import replaces it), and is
    /// serialized only when non-empty so non-module devices stay diff-clean.
    ///
    /// # Why it exists
    ///
    /// A module parameter's effective memory offset is
    /// `declared Offset + instance_base`, where `instance_base` is the value of
    /// the module argument the parameter's `<Memory BaseOffset>` names. The same
    /// module parameter is instantiated once per channel, so each channel's copy
    /// lands at a different byte; the per-instance base VALUES live only in the
    /// project's `ModuleInstance` arguments (not in the ApplicationProgram), so
    /// without persisting them a module-parameter override cannot be placed and is
    /// refused at pre-flight (issue #48). This map carries exactly those bases so
    /// the flasher can resolve a per-channel address.
    ///
    /// The key is the same module-instance selector the parameter key preserves:
    /// stripping `_P-<p>_R-<r>` from a `parameters:` key's ref-id body yields the
    /// selector that indexes this map. It matches the
    /// [`base_offsets`](../../../bussard_prod/image/fn.compute_parameter_image.html)
    /// contract the parameter-image builder expects, verbatim. Non-module devices
    /// have an empty map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub module_bases: BTreeMap<String, u32>,
    /// Generated com-object table, keyed by com-object number.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub com_objects: BTreeMap<u16, ComObject>,
    /// KNX Secure status flags (issue #71, spec §11). **Flags and seqnum state
    /// only** — the committed YAML NEVER carries a key, FDSK, or password
    /// (spec §2.2). Absent (`None`) for a plain, non-secure-capable device so
    /// existing device files are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<DeviceSecurity>,
}

/// The KNX Secure status of a device, recorded as flags-only in the committed
/// YAML model (issue #71, spec §11 / §2.2).
///
/// This carries **no key material**: it records whether the device's application
/// is Data-Secure-capable, whether a factory device certificate (FDSK) was
/// present in the imported knxproj, and the ETS-tracked Data Secure sequence
/// state. Key bytes (FDSK, tool key, group key, passwords) live only in a
/// separate, gitignored local keystore / the in-memory keyring, never here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeviceSecurity {
    /// The device's application declares `IsSecureEnabled="true"`: it can run KNX
    /// Data Secure (spec §11). Capability, not activation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secure_capable: bool,
    /// Security has been **activated** on the device (ETS loaded its tool key
    /// into it). When true, all management access must go behind A_SecureData
    /// tool-access (spec §6.4). CONFIRMED signal (issue #156, the export made
    /// after ETS activated 1.1.12): the device's `<Security>` child carries a
    /// `LoadedToolKey` attribute. A sequence number alone is not the signal:
    /// every secure-capable device carries one before activation too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub activated: bool,
    /// Secure commissioning is enabled for the device in the project (its
    /// `<Security>` child carries a `ToolKey`), whether or not ETS has
    /// downloaded it yet. `secure_commissioning && !activated` is a device ETS
    /// will activate on its next download. Presence only, never the key.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secure_commissioning: bool,
    /// A factory `<DeviceCertificate FDSK=…>` was present in the imported
    /// knxproj (spec §11). Presence only — the FDSK value is never stored here.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_fdsk_certificate: bool,
    /// The ETS-tracked Data Secure sequence number for this device, if the
    /// knxproj `<Security SequenceNumber>` carried one (spec §5.9 / §11). Machine
    /// state used to seed the send sequence so a new run does not replay a stale
    /// value; not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,
}

/// A device's physical location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    /// Floor, e.g. `"EG"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<String>,
    /// Room, e.g. `"Wohnzimmer"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
}

/// Product identity for a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    /// Manufacturer name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// Manufacturer reference id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer_ref: Option<String>,
    /// Order number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_number: Option<String>,
    /// Hardware reference id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_ref: Option<String>,
    /// Application program reference id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_ref: Option<String>,
    /// Mask version (decides property- vs memory-based links).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
}

/// A named device channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    /// Channel display name.
    pub name: String,
}

/// A single generated com object on a device.
///
/// The informational name lives in `links.yaml` (the single home for it — see
/// issue #19), not here. The on-wire payload size is a pure function of the DPT
/// (see [`Dpt::expected_size`]); it is only serialized in the rare case where a
/// com-object has no DPT at all, so nothing about it can otherwise be inferred
/// (issue #17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ComObject {
    /// Datapoint type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpt: Option<Dpt>,
    /// Declared size string (e.g. `"1 bit"`), serialized *only* when no `dpt`
    /// is present (otherwise the size is derived from the DPT on demand).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// Communication flags.
    pub flags: Flags,
    /// Cross-reference id from the product data (`ref` is a keyword).
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Owning channel key, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Whether this group object communicates with KNX Data Secure (issue
    /// #156): its ETS `Security` setting is `On`, or `Auto` (the default) with
    /// a secured group address linked. A secured download writes `0x03`
    /// (authentication + confidentiality) for it into the security object's
    /// `PID_GO_SECURITY_FLAGS`. Serialized only when `true`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secure: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn test_keyring_path_resolves_relative_to_the_model_dir()
    -> Result<(), Box<dyn std::error::Error>> {
        let config: BussardConfig = serde_norway::from_str(
            "connection:\n  transport: tunnel\n  keyring: ../keys/site.knxkeys\n",
        )?;
        assert_eq!(
            config.connection.keyring_path(Path::new("/repo/knx")),
            Some(PathBuf::from("/repo/knx/../keys/site.knxkeys"))
        );
        Ok(())
    }

    #[test]
    fn test_keyring_path_keeps_an_absolute_path() {
        let connection = Connection {
            keyring: Some(PathBuf::from("/secrets/site.knxkeys")),
            ..Connection::default()
        };
        assert_eq!(
            connection.keyring_path(Path::new("/repo/knx")),
            Some(PathBuf::from("/secrets/site.knxkeys"))
        );
        assert_eq!(Connection::default().keyring_path(Path::new("/x")), None);
    }
}
