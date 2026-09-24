//! The optional `ha.toml` overrides file.
//!
//! `ha.toml` lives alongside the model (in the same directory passed to
//! `bussard ha-config`). It is entirely optional: when absent, an empty set of
//! overrides is used and derivation runs on heuristics alone. When present it is
//! parsed *strictly* — unknown fields and duplicate keys are rejected — so a
//! typo surfaces as an error rather than being silently ignored.
//!
//! # Format
//!
//! ```yaml
//! # ha.toml — overrides for `bussard ha-config`.
//! global:
//!   # Whether a plain switchable actuator becomes a `switch` (default) or a
//!   # `light` entity.
//!   default_platform_for_switches: switch   # or: light
//!   # Group addresses (or GA prefixes ending in `/`) to skip entirely. A GA
//!   # here is dropped from derivation and does not appear in the unmapped
//!   # summary either.
//!   exclude:
//!     - "0/0/1"       # a single GA
//!     - "8/"          # every GA under main group 8
//!     - "4/1/"        # every GA under 4/1
//!
//! # Per-entity overrides, keyed by the entity's *primary* group address (the
//! # address HA sends to: `address` for switch/light/cover, `state_address` for
//! # sensor/binary_sensor).
//! entities:
//!   "1/0/1":
//!     platform: light          # force switch -> light
//!     name: "Kitchen ceiling"  # override the derived name
//!     device_class: outlet     # set/override the HA device_class
//!   "3/1/5":
//!     # Merge extra listening GAs onto the entity (e.g. a second state GA).
//!     merge: ["3/1/6"]
//! ```
//!
//! Override precedence: exclusions win over everything (an excluded GA never
//! produces an entity, and an excluded GA listed in a `merge` is ignored); an
//! explicit per-entity `platform` overrides the heuristic; an explicit
//! `name`/`device_class` overrides the derived value; `merge` attaches the
//! listed GAs to the entity — wiring each into a free state slot where the
//! platform has one and folding them all into the entity's claimed set (see
//! [`EntityOverride::merge`] for the exact per-platform behaviour).

use std::collections::BTreeMap;
use std::path::Path;

use bussard_model::GroupAddress;
use serde::Deserialize;

/// A parse error for `ha.toml`.
#[derive(Debug, thiserror::Error)]
pub enum OverridesError {
    /// An I/O error reading the file.
    #[error("reading {path}: {source}")]
    Io {
        /// The path being read.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The YAML was syntactically invalid or contained a duplicate key.
    #[error("parsing {path}: {source}")]
    Yaml {
        /// The offending file.
        path: String,
        /// The underlying parse error.
        source: serde_norway::Error,
    },
    /// The YAML parsed but did not match the schema.
    #[error("in {path} at `{yaml_path}`: {message}")]
    Schema {
        /// The offending file.
        path: String,
        /// Human-readable YAML path to the offending value.
        yaml_path: String,
        /// The error message.
        message: String,
    },
}

/// The platform a switchable actuator maps to when no per-entity override applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SwitchPlatform {
    /// Map to a Home Assistant `switch` entity (the default).
    #[default]
    Switch,
    /// Map to a Home Assistant `light` entity.
    Light,
}

/// The full contents of a parsed `ha.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    /// Global settings.
    #[serde(default)]
    pub global: Global,
    /// Per-entity overrides, keyed by primary GA (as a raw string so prefixes
    /// and exact GAs share one namespace at the parse boundary; validated into
    /// [`GroupAddress`] on use).
    #[serde(default)]
    pub entities: BTreeMap<String, EntityOverride>,
}

/// Global overrides.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Global {
    /// The platform a plain switchable actuator maps to.
    #[serde(default)]
    pub default_platform_for_switches: SwitchPlatform,
    /// GAs or GA prefixes (ending in `/`) to skip entirely.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// A per-entity override, keyed by the entity's primary GA.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EntityOverride {
    /// Force a specific platform for this entity.
    #[serde(default)]
    pub platform: Option<PlatformOverride>,
    /// Override the derived entity name.
    #[serde(default)]
    pub name: Option<String>,
    /// Set or override the HA `device_class`.
    #[serde(default)]
    pub device_class: Option<String>,
    /// Extra group addresses to merge onto this entity (e.g. a state GA the
    /// heuristic did not associate).
    ///
    /// Applied after the entity is derived, for the entity whose *primary* GA is
    /// this override's key. Each merged GA is attached to the entity and folded
    /// into its group-address set, so it is claimed (no other entity re-maps it)
    /// and no longer reported in the unmapped footer. Per platform:
    ///
    /// - **switch / light**: the first merged GA fills a free `state_address`;
    ///   any further merged GAs are still consumed but have no slot to occupy.
    /// - **cover**: the first free of `position_state_address` then
    ///   `angle_state_address` is filled; extras are consumed only.
    /// - **sensor / binary_sensor**: these have a single address and no spare
    ///   state slot, so merged GAs are consumed only (claimed + removed from the
    ///   unmapped summary) without being wired anywhere.
    ///
    /// Merge never overwrites a GA the heuristic already derived, and never
    /// overwrites a merged GA that an earlier entity already owns. Exclusion wins
    /// over merge: an excluded GA listed in `merge` is ignored.
    #[serde(default)]
    pub merge: Vec<GroupAddress>,
}

/// A per-entity platform override.
///
/// Only the transitions that make sense are offered: a derived `switch` can be
/// promoted to a `light` and vice-versa. Other platforms (cover, sensor,
/// binary_sensor) are structural and are not overridable this way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformOverride {
    /// Force a `switch` entity.
    Switch,
    /// Force a `light` entity.
    Light,
}

impl Overrides {
    /// Loads `ha.toml` from `dir`, returning defaults when the file is absent.
    ///
    /// Parsing is strict: duplicate keys and unknown fields are rejected.
    pub fn load(dir: &Path) -> Result<Self, OverridesError> {
        let path = dir.join("ha.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).map_err(|source| OverridesError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&path.display().to_string(), &text)
    }

    /// Parses `ha.toml` text, rejecting duplicate keys and unknown fields.
    pub fn parse(path: &str, text: &str) -> Result<Self, OverridesError> {
        // Stage 1: parse into an untyped value (rejects duplicate keys).
        let value: serde_norway::Value =
            serde_norway::from_str(text).map_err(|source| OverridesError::Yaml {
                path: path.to_string(),
                source,
            })?;
        // Stage 2: deserialize into the typed struct with a YAML path on errors.
        serde_path_to_error::deserialize(value).map_err(|err| {
            let yaml_path = err.path().to_string();
            OverridesError::Schema {
                path: path.to_string(),
                yaml_path: if yaml_path.is_empty() {
                    ".".to_string()
                } else {
                    yaml_path
                },
                message: err.into_inner().to_string(),
            }
        })
    }

    /// Whether a group address is excluded (by exact match or prefix).
    ///
    /// A prefix entry ends in `/` and matches any GA whose string form starts
    /// with it (`"8/"` matches `8/0/1`; `"4/1/"` matches `4/1/9`).
    pub fn is_excluded(&self, ga: GroupAddress) -> bool {
        let s = ga.to_string();
        self.global.exclude.iter().any(|pat| {
            if let Some(prefix) = pat.strip_suffix('/') {
                // A prefix like "8" or "4/1". Match on a `/`-delimited boundary.
                s == prefix || s.starts_with(&format!("{prefix}/"))
            } else {
                s == *pat
            }
        })
    }

    /// The override for an entity whose primary GA is `ga`, if any.
    pub fn entity(&self, ga: GroupAddress) -> Option<&EntityOverride> {
        self.entities.get(&ga.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }

    #[test]
    fn absent_file_is_default() {
        let dir = std::env::temp_dir().join(format!("bussard-ha-no-ha-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let ov = Overrides::load(&dir).unwrap();
        assert_eq!(ov, Overrides::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_full_example() {
        let text = r#"
global:
  default_platform_for_switches: light
  exclude:
    - "0/0/1"
    - "8/"
entities:
  "1/0/1":
    platform: light
    name: "Kitchen"
    device_class: outlet
  "3/1/5":
    merge: ["3/1/6"]
"#;
        let ov = Overrides::parse("ha.toml", text).unwrap();
        assert_eq!(
            ov.global.default_platform_for_switches,
            SwitchPlatform::Light
        );
        assert!(ov.is_excluded(ga("0/0/1")));
        assert!(ov.is_excluded(ga("8/0/5")));
        assert!(!ov.is_excluded(ga("9/0/0")));
        let e = ov.entity(ga("1/0/1")).unwrap();
        assert_eq!(e.platform, Some(PlatformOverride::Light));
        assert_eq!(e.name.as_deref(), Some("Kitchen"));
        assert_eq!(e.device_class.as_deref(), Some("outlet"));
        let m = ov.entity(ga("3/1/5")).unwrap();
        assert_eq!(m.merge, vec![ga("3/1/6")]);
    }

    #[test]
    fn rejects_unknown_field() {
        let text = "global:\n  bogus: 1\n";
        assert!(matches!(
            Overrides::parse("ha.toml", text),
            Err(OverridesError::Schema { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_key() {
        let text = "entities:\n  \"1/0/1\": {}\n  \"1/0/1\": {}\n";
        assert!(matches!(
            Overrides::parse("ha.toml", text),
            Err(OverridesError::Yaml { .. })
        ));
    }

    #[test]
    fn prefix_exclusion_respects_boundaries() {
        let text = "global:\n  exclude:\n    - \"1/\"\n";
        let ov = Overrides::parse("ha.toml", text).unwrap();
        assert!(ov.is_excluded(ga("1/0/0")));
        assert!(ov.is_excluded(ga("1/7/255")));
        // main group 10 must not be caught by the "1/" prefix.
        assert!(!ov.is_excluded(ga("10/0/0")));
    }
}
