//! The keyring rules of `bussard validate` (issue #205).
//!
//! The model never holds key material, and this crate cannot decrypt an ETS
//! `.knxkeys` export. The caller (the CLI's `validate`, the MCP server's
//! `knx_validate`) resolves the keyring, decrypts it at most once and passes
//! what it found as [`KeyringFacts`]: the devices the keyring holds a tool key
//! for and the group addresses it holds a group key for. Only addresses cross
//! into this module, never a key.
//!
//! * **E027**: the configured keyring file does not exist (error).
//! * **W028**: a device file says `security.activated = true`, but no keyring
//!   is configured, the keyring is missing, or it has no tool key for the
//!   device. Secured management of that device needs a keyring ETS exported
//!   after its security was commissioned.
//! * **W029**: a group's `secure` flag disagrees with the keyring: marked
//!   secure without a group key, or keyed in the keyring but not marked secure.
//! * **W030**: the keyring does not read or decrypt; the key checks are
//!   skipped.
//! * **I031**: `BUSSARD_KEYRING_PASSWORD` is not set; the key checks are
//!   skipped (`validate` never prompts).

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::address::{GroupAddress, IndividualAddress};
use crate::loader::Model;
use crate::validate::{Diagnostic, Severity};

/// The environment variable holding the keyring password, named in the
/// messages. The same name `bussard-service` reads.
pub const KEYRING_PASSWORD_ENV: &str = "BUSSARD_KEYRING_PASSWORD";

/// What the caller found out about the configured keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringFacts {
    /// The keyring file.
    pub path: PathBuf,
    /// Where the path came from, for the messages: `connection.keyring in
    /// bussard.toml`, `BUSSARD_KEYRING`, `the server's keyring`.
    pub source: String,
    /// Whether the key checks can run.
    pub status: KeyringStatus,
}

/// The state of a configured keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringStatus {
    /// The file does not exist.
    Missing,
    /// The file exists, but [`KEYRING_PASSWORD_ENV`] is not set.
    Locked,
    /// The file does not read or decrypt; the reason names no key.
    Unreadable(String),
    /// Decrypted: which devices and group addresses it holds keys for.
    Loaded {
        /// Devices with a tool key.
        tool_keys: BTreeSet<IndividualAddress>,
        /// Group addresses with a group key.
        group_keys: BTreeSet<GroupAddress>,
    },
}

/// The keyring diagnostics for `model` (see the module docs), given what the
/// caller found for the configured keyring (`None`: no keyring configured).
/// Sorted like [`crate::validate()`]'s output.
pub fn validate_keyring(model: &Model, keyring: Option<&KeyringFacts>) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let activated: Vec<(IndividualAddress, String)> = model
        .devices
        .iter()
        .filter(|(_, d)| d.device.security.as_ref().is_some_and(|s| s.activated))
        .map(|(ia, d)| {
            (
                *ia,
                format!("devices/{}.toml security.activated", d.file_stem),
            )
        })
        .collect();

    let Some(facts) = keyring else {
        for (ia, location) in &activated {
            diags.push(Diagnostic::new(
                "W028",
                Severity::Warning,
                location.clone(),
                format!(
                    "{ia} is KNX Data Secure-activated but no keyring is configured; export the \
                     project's keyring (.knxkeys) from ETS and set `connection.keyring` in \
                     bussard.toml (or BUSSARD_KEYRING) so bussard can manage it secured"
                ),
            ));
        }
        return sorted(diags);
    };
    let file = facts.path.display();
    match &facts.status {
        KeyringStatus::Missing => {
            diags.push(Diagnostic::new(
                "E027",
                Severity::Error,
                facts.source.clone(),
                format!(
                    "the keyring {file} ({}) does not exist; fix the path or re-export the \
                     keyring from ETS",
                    facts.source
                ),
            ));
            for (ia, location) in &activated {
                diags.push(Diagnostic::new(
                    "W028",
                    Severity::Warning,
                    location.clone(),
                    format!(
                        "{ia} is KNX Data Secure-activated but the keyring {file} is missing; \
                         secured management of it needs the keyring re-exported from ETS"
                    ),
                ));
            }
        }
        KeyringStatus::Locked => diags.push(Diagnostic::new(
            "I031",
            Severity::Info,
            facts.source.clone(),
            format!(
                "{KEYRING_PASSWORD_ENV} is not set, so the keyring {file} was not checked \
                 against the model's secured devices and groups"
            ),
        )),
        KeyringStatus::Unreadable(reason) => diags.push(Diagnostic::new(
            "W030",
            Severity::Warning,
            facts.source.clone(),
            format!(
                "the keyring {file} could not be read ({reason}); its tool and group keys were \
                 not checked against the model"
            ),
        )),
        KeyringStatus::Loaded {
            tool_keys,
            group_keys,
        } => {
            for (ia, location) in &activated {
                if !tool_keys.contains(ia) {
                    diags.push(Diagnostic::new(
                        "W028",
                        Severity::Warning,
                        location.clone(),
                        format!(
                            "{ia} is KNX Data Secure-activated but the keyring {file} has no \
                             tool key for it; re-export the keyring from ETS (it lists a device \
                             only after its security was commissioned there)"
                        ),
                    ));
                }
            }
            for (ga, group) in &model.groups.groups {
                let keyed = group_keys.contains(ga);
                let location = format!("groups.toml {ga}");
                if group.secure && !keyed {
                    diags.push(Diagnostic::new(
                        "W029",
                        Severity::Warning,
                        location,
                        format!(
                            "GA {ga} is marked `secure = true` but the keyring {file} has no \
                             group key for it; export a current keyring from ETS or drop the \
                             flag"
                        ),
                    ));
                } else if keyed && !group.secure {
                    diags.push(Diagnostic::new(
                        "W029",
                        Severity::Warning,
                        location,
                        format!(
                            "the keyring {file} holds a group key for GA {ga}, but groups.toml \
                             does not mark it `secure = true`; secured devices on it expect \
                             encrypted telegrams"
                        ),
                    ));
                }
            }
        }
    }
    sorted(diags)
}

/// Sorts diagnostics by `(location, code)`, as every rule pass does.
fn sorted(mut diags: Vec<Diagnostic>) -> Vec<Diagnostic> {
    diags.sort_by(|a, b| a.location.cmp(&b.location).then(a.code.cmp(b.code)));
    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::LoadedDevice;
    use crate::schema::{BussardConfig, Device, DeviceSecurity, Group, Groups, Links};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A model with activated 1.1.12 and 1.1.13, plain 1.1.4, GA 1/2/3 marked
    /// secure and GA 1/2/4 plain.
    fn model() -> Result<Model, Box<dyn std::error::Error>> {
        let mut devices = BTreeMap::new();
        for (ia, activated) in [("1.1.4", false), ("1.1.12", true), ("1.1.13", true)] {
            let address: IndividualAddress = ia.parse()?;
            let device = Device {
                address,
                name: format!("Device {ia}"),
                description: None,
                location: None,
                product: None,
                channels: BTreeMap::new(),
                parameters: BTreeMap::new(),
                module_bases: BTreeMap::new(),
                com_objects: BTreeMap::new(),
                security: activated.then(|| DeviceSecurity {
                    activated: true,
                    ..DeviceSecurity::default()
                }),
                replaced: None,
                application_override: None,
                lock: Default::default(),
            };
            devices.insert(
                address,
                LoadedDevice {
                    device,
                    file_stem: ia.to_string(),
                },
            );
        }
        let mut groups = BTreeMap::new();
        groups.insert(
            "1/2/3".parse()?,
            Group {
                name: "Secured".to_string(),
                secure: true,
                ..Group::default()
            },
        );
        groups.insert(
            "1/2/4".parse()?,
            Group {
                name: "Plain".to_string(),
                ..Group::default()
            },
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups {
                groups,
                ..Groups::default()
            },
            links: Links::default(),
            devices,
        })
    }

    fn facts(status: KeyringStatus) -> KeyringFacts {
        KeyringFacts {
            path: PathBuf::from("site.knxkeys"),
            source: "connection.keyring in bussard.toml".to_string(),
            status,
        }
    }

    fn codes(diags: &[Diagnostic]) -> Vec<(&'static str, String)> {
        diags.iter().map(|d| (d.code, d.location.clone())).collect()
    }

    #[test]
    fn test_validate_keyring_without_a_keyring_warns_per_activated_device() -> TestResult {
        let diags = validate_keyring(&model()?, None);
        assert_eq!(
            codes(&diags),
            vec![
                ("W028", "devices/1.1.12.toml security.activated".to_string()),
                ("W028", "devices/1.1.13.toml security.activated".to_string()),
            ]
        );
        assert!(diags[0].message.contains("connection.keyring"), "{diags:?}");
        Ok(())
    }

    #[test]
    fn test_validate_keyring_missing_file_is_an_error() -> TestResult {
        let diags = validate_keyring(&model()?, Some(&facts(KeyringStatus::Missing)));
        let e027: Vec<_> = diags.iter().filter(|d| d.code == "E027").collect();
        assert_eq!(e027.len(), 1, "{diags:?}");
        assert_eq!(e027[0].severity, Severity::Error);
        assert!(e027[0].message.contains("site.knxkeys"), "{diags:?}");
        assert_eq!(diags.iter().filter(|d| d.code == "W028").count(), 2);
        assert!(crate::has_errors(&diags));
        Ok(())
    }

    #[test]
    fn test_validate_keyring_locked_emits_one_info_and_skips_the_key_checks() -> TestResult {
        let diags = validate_keyring(&model()?, Some(&facts(KeyringStatus::Locked)));
        assert_eq!(codes(&diags).len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "I031");
        assert!(diags[0].message.contains(KEYRING_PASSWORD_ENV));
        Ok(())
    }

    #[test]
    fn test_validate_keyring_unreadable_warns_once() -> TestResult {
        let status = KeyringStatus::Unreadable("wrong password".to_string());
        let diags = validate_keyring(&model()?, Some(&facts(status)));
        assert_eq!(codes(&diags).len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "W030");
        Ok(())
    }

    #[test]
    fn test_validate_keyring_loaded_names_the_missing_tool_key_and_flag_mismatches() -> TestResult {
        let status = KeyringStatus::Loaded {
            tool_keys: BTreeSet::from(["1.1.12".parse()?]),
            group_keys: BTreeSet::from(["1/2/4".parse()?, "9/7/9".parse()?]),
        };
        let diags = validate_keyring(&model()?, Some(&facts(status)));
        assert_eq!(
            codes(&diags),
            vec![
                ("W028", "devices/1.1.13.toml security.activated".to_string()),
                ("W029", "groups.toml 1/2/3".to_string()),
                ("W029", "groups.toml 1/2/4".to_string()),
            ]
        );
        assert!(diags[0].message.contains("re-export"), "{diags:?}");
        assert!(diags[1].message.contains("no group key"), "{diags:?}");
        assert!(diags[2].message.contains("does not mark"), "{diags:?}");
        Ok(())
    }

    #[test]
    fn test_validate_keyring_loaded_and_consistent_is_clean() -> TestResult {
        let status = KeyringStatus::Loaded {
            tool_keys: BTreeSet::from(["1.1.12".parse()?, "1.1.13".parse()?]),
            group_keys: BTreeSet::from(["1/2/3".parse()?]),
        };
        assert!(validate_keyring(&model()?, Some(&facts(status))).is_empty());
        Ok(())
    }
}
