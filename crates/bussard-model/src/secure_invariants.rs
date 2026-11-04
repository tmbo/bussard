//! KNX Data Secure consistency invariants (issue #348), next to the link
//! checks of [`crate::secure_links`] (E035, E036).
//!
//! The model-only rules, run by every validation:
//!
//! * **W037**: a Secure-capable device runs a secured group address but its
//!   security is not activated (ETS has not loaded its tool key). Until a
//!   download activates it the device sends and expects plain telegrams, so
//!   its secured partners drop what it sends and it cannot decrypt theirs.
//! * **W039**: an activated device sends on a secured group address, but
//!   `bussard.lock` records no Data Secure sequence number for it. The
//!   receivers' security individual address tables (PID 54) hold the last
//!   sequence they accepted from each sender; without a recorded source a
//!   download can only seed the entry from the keyring or with 0.
//! * **W041**: the group's `secure` flag and the `secure` flags of the
//!   Secure-capable objects linked to it disagree. With W029 (the flag
//!   against the key store) it is the three-signal check of issue #331, and
//!   the message names the command that sets all three at once.
//!
//! The command-time rule, printed by `bussard import` and `bussard keys
//! import`:
//!
//! * **W042**: a re-import secures a group address the model ran plain, or a
//!   `keys import` puts back the group key of one: the next apply secures it
//!   again on the devices it names.
//!
//! Nothing here reads a key: only flags and addresses.

use std::collections::{BTreeMap, BTreeSet};

use crate::address::{GroupAddress, IndividualAddress};
use crate::loader::Model;
use crate::validate::{Diagnostic, Severity};

/// One linked object, as the invariants see it.
struct LinkedObject {
    device: IndividualAddress,
    object: u16,
    sends: bool,
    /// The object's own `secure` flag in the lock.
    object_secure: bool,
}

/// Every linked object of a device that has a lock entry for it, by group
/// address.
fn linked_objects(model: &Model) -> BTreeMap<GroupAddress, Vec<LinkedObject>> {
    let mut by_ga: BTreeMap<GroupAddress, Vec<LinkedObject>> = BTreeMap::new();
    for (ia, links) in &model.links.links {
        let Some(loaded) = model.devices.get(ia) else {
            continue;
        };
        for link in links {
            let object_secure = loaded
                .device
                .com_objects
                .get(&link.object)
                .is_some_and(|co| co.secure);
            let mut gas: Vec<GroupAddress> = link.send.into_iter().collect();
            gas.extend(link.listen.iter().copied());
            gas.sort();
            gas.dedup();
            for ga in gas {
                by_ga.entry(ga).or_default().push(LinkedObject {
                    device: *ia,
                    object: link.object,
                    sends: link.send == Some(ga),
                    object_secure,
                });
            }
        }
    }
    by_ga
}

/// Whether `ia` can run KNX Data Secure.
fn capable(model: &Model, ia: IndividualAddress) -> bool {
    model
        .devices
        .get(&ia)
        .and_then(|d| d.device.security.as_ref())
        .is_some_and(|s| s.secure_capable)
}

/// Whether the model marks `ga` secure.
fn group_secure(model: &Model, ga: GroupAddress) -> bool {
    model.groups.groups.get(&ga).is_some_and(|g| g.secure)
}

/// A list of group addresses as `1/0/4, 1/0/5`.
fn join<T: ToString>(items: impl IntoIterator<Item = T>) -> String {
    items
        .into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The model-only invariants: W037, W039 and W041.
pub(crate) fn check_secure_invariants(model: &Model, diags: &mut Vec<Diagnostic>) {
    let by_ga = linked_objects(model);

    // The secured group addresses each Secure-capable device runs, and the
    // ones it sends on.
    let mut runs: BTreeMap<IndividualAddress, BTreeSet<GroupAddress>> = BTreeMap::new();
    let mut sends: BTreeMap<IndividualAddress, BTreeSet<GroupAddress>> = BTreeMap::new();
    for (ga, objects) in &by_ga {
        for o in objects.iter().filter(|o| capable(model, o.device)) {
            if o.object_secure || group_secure(model, *ga) {
                runs.entry(o.device).or_default().insert(*ga);
                if o.sends {
                    sends.entry(o.device).or_default().insert(*ga);
                }
            }
        }
    }

    for (ia, gas) in &runs {
        let Some(loaded) = model.devices.get(ia) else {
            continue;
        };
        let Some(security) = loaded.device.security.as_ref() else {
            continue;
        };
        if security.activated {
            continue;
        }
        let list = join(gas);
        let message = if security.secure_commissioning {
            format!(
                "{ia} runs the secured {list}, but ETS set it up for Secure commissioning and it \
                 is not secured yet (no tool key loaded), so it still sends and expects plain \
                 telegrams: its secured partners drop what it sends and it cannot decrypt what \
                 they send. Download it from ETS, which secures it, then re-import the project \
                 and `bussard keys import` the new ETS keyring"
            )
        } else {
            format!(
                "{ia} can run KNX Data Secure and is linked to the secured {list}, but it is not \
                 secured, so it sends and expects plain telegrams: its secured \
                 partners drop what it sends and it cannot decrypt what they send. Turn on \
                 Secure commissioning for it in ETS and download it, or run the addresses plain \
                 (`bussard groups secure <ga> off`)"
            )
        };
        diags.push(Diagnostic::new(
            "W037",
            Severity::Warning,
            format!("devices/{}.toml security", loaded.file_stem),
            message,
        ));
    }

    for (ia, gas) in &sends {
        let Some(loaded) = model.devices.get(ia) else {
            continue;
        };
        let Some(security) = loaded.device.security.as_ref() else {
            continue;
        };
        if !security.activated || security.sequence_number.is_some() {
            continue;
        }
        diags.push(Diagnostic::new(
            "W039",
            Severity::Warning,
            format!("bussard.lock device {ia}"),
            format!(
                "{ia} sends secured on {}, but bussard.lock records no Data Secure sequence \
                 number for it (`sequence_number`): a download of its receivers can then only \
                 seed their security individual address tables (PID 54) from the key store or \
                 with 0, which accepts replayed telegrams. Re-import the ETS project (it carries \
                 the device's SequenceNumber) or run `bussard adopt {ia}`",
                join(gas)
            ),
        ));
    }

    // W041: the group flag against the flags of the Secure-capable objects.
    // An object that runs another, secured address of its own legitimately
    // carries the flag on a plain one, so only an object whose every address
    // is plain counts against a plain group.
    let mut secured_gas_of: BTreeMap<(IndividualAddress, u16), bool> = BTreeMap::new();
    for (ga, objects) in &by_ga {
        for o in objects {
            let any = secured_gas_of.entry((o.device, o.object)).or_default();
            *any |= group_secure(model, *ga);
        }
    }
    for (ga, objects) in &by_ga {
        let Some(group) = model.groups.groups.get(ga) else {
            continue;
        };
        let capable_objects = objects.iter().filter(|o| capable(model, o.device));
        let disagree: Vec<String> = if group.secure {
            capable_objects
                .filter(|o| !o.object_secure)
                .map(|o| format!("{} object {}", o.device, o.object))
                .collect()
        } else {
            capable_objects
                .filter(|o| {
                    o.object_secure
                        && !secured_gas_of
                            .get(&(o.device, o.object))
                            .copied()
                            .unwrap_or(false)
                })
                .map(|o| format!("{} object {}", o.device, o.object))
                .collect()
        };
        if disagree.is_empty() {
            continue;
        }
        let objects = disagree.join(", ");
        let message = if group.secure {
            format!(
                "group address {ga} is marked `secure = true`, but {objects} on it {} not secured in \
                 bussard.lock: the group flag, the key store and the object flags must agree. \
                 Fix: `bussard groups secure {ga} on` sets all three (or `off` to run {ga} \
                 plain)",
                if disagree.len() == 1 { "is" } else { "are" }
            )
        } else {
            format!(
                "group address {ga} is plain, but {objects} on it {} secured in bussard.lock and has no \
                 secured address besides it: the group flag, the key store and the object flags \
                 must agree. Fix: `bussard groups secure {ga} off` clears all three (or `on` to \
                 secure {ga})",
                if disagree.len() == 1 { "is" } else { "are" }
            )
        };
        diags.push(Diagnostic::new(
            "W041",
            Severity::Warning,
            format!("groups.toml {ga}"),
            message,
        ));
    }
}

/// The devices linked to `ga`, ascending.
fn devices_on(model: &Model, ga: GroupAddress) -> Vec<IndividualAddress> {
    model
        .links
        .links
        .iter()
        .filter(|(_, links)| {
            links
                .iter()
                .any(|l| l.send == Some(ga) || l.listen.contains(&ga))
        })
        .map(|(ia, _)| *ia)
        .collect()
}

/// W042 for a re-import (issue #348): the group addresses `before` ran plain
/// that `after` (the merged import) secures again, each naming the devices
/// that need a plan and apply to follow. Empty when nothing was re-secured.
pub fn resecured_by_import(before: &Model, after: &Model) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for (ga, group) in &after.groups.groups {
        let was_plain = before.groups.groups.get(ga).is_some_and(|g| !g.secure);
        if !group.secure || !was_plain {
            continue;
        }
        let devices = devices_on(after, *ga);
        let apply = if devices.is_empty() {
            "no device is linked to it yet".to_string()
        } else {
            format!(
                "{} then {} `bussard plan` and `bussard apply` to run it secured",
                join(&devices),
                if devices.len() == 1 { "needs" } else { "need" }
            )
        };
        out.push(Diagnostic::new(
            "W042",
            Severity::Warning,
            format!("groups.toml {ga}"),
            format!(
                "the ETS project secures {ga} again, which your project ran plain; {apply}. To \
                 keep it plain, run `bussard groups secure {ga} off` (and set it plain in ETS so \
                 the next import agrees)"
            ),
        ));
    }
    out
}

/// W042 for `bussard keys import` (issue #348): the group keys the import
/// added for group addresses the model runs plain. A group address whose key
/// is in the key store is secured by the next download, so each warning
/// names the devices that would change. Addresses the model does not define
/// are skipped.
pub fn rekeyed_by_keys_import(model: &Model, added: &[GroupAddress]) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for ga in added {
        let Some(group) = model.groups.groups.get(ga) else {
            continue;
        };
        if group.secure {
            continue;
        }
        let devices = devices_on(model, *ga);
        let who = if devices.is_empty() {
            "the devices linked to it later".to_string()
        } else {
            join(&devices)
        };
        out.push(Diagnostic::new(
            "W042",
            Severity::Warning,
            format!("groups.toml {ga}"),
            format!(
                "the imported ETS keyring puts back the group key of {ga}, which your project \
                 runs plain; the next apply of {who} would secure {ga} again. Run `bussard groups \
                 secure {ga} off` to drop the key, or `bussard groups secure {ga} on` and apply \
                 {who} to run it secured"
            ),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::LoadedDevice;
    use crate::schema::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A device with one 1-bit object `object` (flags CWTU).
    fn device(
        addr: &str,
        security: Option<DeviceSecurity>,
        object: u16,
        secure_object: bool,
    ) -> Result<LoadedDevice, Box<dyn std::error::Error>> {
        Ok(LoadedDevice {
            device: Device {
                address: addr.parse()?,
                name: format!("dev {addr}"),
                description: None,
                location: None,
                replaced: None,
                product: None,
                channels: BTreeMap::new(),
                parameters: BTreeMap::new(),
                module_bases: BTreeMap::new(),
                com_objects: [(
                    object,
                    ComObject {
                        dpt: Some("1.001".parse()?),
                        flags: "CWTU".parse()?,
                        secure: secure_object,
                        ..ComObject::default()
                    },
                )]
                .into_iter()
                .collect(),
                security,
                application_override: None,
                knxnet: None,
                lock: Default::default(),
            },
            file_stem: addr.to_string(),
        })
    }

    fn activated(sequence: Option<u64>) -> Option<DeviceSecurity> {
        Some(DeviceSecurity {
            secure_capable: true,
            activated: true,
            secure_commissioning: true,
            sequence_number: sequence,
            ..DeviceSecurity::default()
        })
    }

    /// Secured 1/0/4: 1.1.10 sends on it, 1.1.5 listens; both activated,
    /// both objects secured.
    fn model() -> Result<Model, Box<dyn std::error::Error>> {
        let ga: GroupAddress = "1/0/4".parse()?;
        let mut groups = BTreeMap::new();
        groups.insert(
            ga,
            Group {
                name: "Licht".into(),
                dpt: Some("1.001".parse()?),
                secure: true,
                ..Group::default()
            },
        );
        let mut links = BTreeMap::new();
        links.insert(
            "1.1.10".parse()?,
            vec![Link {
                object: 1,
                name: None,
                send: Some(ga),
                listen: vec![],
            }],
        );
        links.insert(
            "1.1.5".parse()?,
            vec![Link {
                object: 3,
                name: None,
                send: None,
                listen: vec![ga],
            }],
        );
        let mut devices = BTreeMap::new();
        devices.insert(
            "1.1.10".parse()?,
            device("1.1.10", activated(Some(7)), 1, true)?,
        );
        devices.insert(
            "1.1.5".parse()?,
            device("1.1.5", activated(Some(9)), 3, true)?,
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links { links },
            devices,
        })
    }

    fn codes(model: &Model) -> Vec<&'static str> {
        let mut diags = Vec::new();
        check_secure_invariants(model, &mut diags);
        diags.iter().map(|d| d.code).collect()
    }

    #[test]
    fn test_check_secure_invariants_consistent_model_is_clean() -> TestResult {
        assert!(codes(&model()?).is_empty());
        Ok(())
    }

    #[test]
    fn test_check_secure_invariants_not_activated_is_w037() -> TestResult {
        let mut m = model()?;
        let ia: IndividualAddress = "1.1.5".parse()?;
        if let Some(s) = m
            .devices
            .get_mut(&ia)
            .and_then(|d| d.device.security.as_mut())
        {
            s.activated = false;
        }
        assert_eq!(codes(&m), vec!["W037"]);
        Ok(())
    }

    #[test]
    fn test_check_secure_invariants_sender_without_sequence_is_w039() -> TestResult {
        let mut m = model()?;
        let ia: IndividualAddress = "1.1.10".parse()?;
        if let Some(s) = m
            .devices
            .get_mut(&ia)
            .and_then(|d| d.device.security.as_mut())
        {
            s.sequence_number = None;
        }
        assert_eq!(codes(&m), vec!["W039"]);
        // A receiver without one is fine: it sends nothing secured.
        let mut m = model()?;
        let ia: IndividualAddress = "1.1.5".parse()?;
        if let Some(s) = m
            .devices
            .get_mut(&ia)
            .and_then(|d| d.device.security.as_mut())
        {
            s.sequence_number = None;
        }
        assert!(codes(&m).is_empty());
        Ok(())
    }

    #[test]
    fn test_check_secure_invariants_object_flag_disagrees_is_w041() -> TestResult {
        let mut m = model()?;
        let ia: IndividualAddress = "1.1.5".parse()?;
        if let Some(co) = m
            .devices
            .get_mut(&ia)
            .and_then(|d| d.device.com_objects.get_mut(&3))
        {
            co.secure = false;
        }
        let mut diags = Vec::new();
        check_secure_invariants(&m, &mut diags);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "W041");
        assert!(
            diags[0].message.contains("bussard groups secure 1/0/4 on"),
            "{}",
            diags[0].message
        );
        Ok(())
    }

    #[test]
    fn test_resecured_by_import_names_devices() -> TestResult {
        let after = model()?;
        let mut before = after.clone();
        for g in before.groups.groups.values_mut() {
            g.secure = false;
        }
        let diags = resecured_by_import(&before, &after);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "W042");
        assert!(
            diags[0].message.contains("1.1.5, 1.1.10"),
            "{}",
            diags[0].message
        );
        assert!(resecured_by_import(&after, &after).is_empty());
        Ok(())
    }

    #[test]
    fn test_rekeyed_by_keys_import_only_plain_groups() -> TestResult {
        let mut m = model()?;
        let ga: GroupAddress = "1/0/4".parse()?;
        assert!(rekeyed_by_keys_import(&m, &[ga]).is_empty());
        for g in m.groups.groups.values_mut() {
            g.secure = false;
        }
        let diags = rekeyed_by_keys_import(&m, &[ga, "9/7/9".parse()?]);
        assert_eq!(diags.len(), 1);
        assert!(
            diags[0].message.contains("1.1.5, 1.1.10"),
            "{}",
            diags[0].message
        );
        Ok(())
    }
}
