//! What `bussard adopt` records for a KNX Data Secure-activated device
//! (issue #201, tier 1).
//!
//! An activated device has been commissioned by ETS: it holds link tables,
//! parameters and a programmed security object. Adopting it reads all of that
//! over `A_SecureData` with the tool key from the keyring (the reads live in
//! `bussard-mgmt` and `bussard-download`); this module turns what was read into
//! model changes, so every surface records a secured device the same way:
//!
//! - [`links_from_tables`]: the device's links from its address and association
//!   tables, with the transmit direction taken from the com-object flags;
//! - [`derive_secure_adoption`]: which group objects and group addresses run
//!   secured, from the keyring's group keys and the group-object security flags
//!   the device reports (PID 61), and where the two disagree;
//! - [`apply_secure_adoption`]: writes the security intent (`activated`,
//!   `secure_commissioning`), the lock facts (`secure_capable`, the keyring
//!   sequence, the sender table read from PID 54) and the `secure` flags into a
//!   [`Model`].
//!
//! Nothing here touches the bus or key bytes: the group keys are only looked up
//! by group address, never copied into the model.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bussard_model::schema::{ComObject, DeviceSecurity, Group, Link, SecureSender};
use bussard_model::{Flags, GroupAddress, IndividualAddress, Model};
use bussard_secure::Key16;

/// Builds the device's links from its resolved association table: `(object,
/// group address)` pairs in table order.
///
/// A KNX device transmits an object's value on the first group address the
/// association table pairs with it, so an object whose flags carry `T` sends on
/// its first address and listens on the rest; any other object listens on all
/// of them. `flags` returns the object's flags from the product data, or `None`
/// when the object is unknown (no product data): such an object listens on
/// every address, as `reconstruct` records it. Links come out in object order.
pub fn links_from_tables(
    resolved: &[(u16, GroupAddress)],
    flags: impl Fn(u16) -> Option<Flags>,
) -> Vec<Link> {
    let mut per_object: BTreeMap<u16, Vec<GroupAddress>> = BTreeMap::new();
    for &(object, ga) in resolved {
        let gas = per_object.entry(object).or_default();
        if !gas.contains(&ga) {
            gas.push(ga);
        }
    }
    per_object
        .into_iter()
        .map(|(object, gas)| {
            let transmits = flags(object).is_some_and(|f| f.contains(Flags::TRANSMIT));
            let mut gas = gas.into_iter();
            let send = if transmits { gas.next() } else { None };
            Link {
                object,
                name: None,
                send,
                listen: gas.collect(),
            }
        })
        .collect()
}

/// The Data Secure view of an adopted device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecureAdoption {
    /// The group objects the model records as `secure`: the device's own
    /// PID 61 flags when they were read, else the objects linked to a keyed
    /// group address.
    pub secure_objects: BTreeSet<u16>,
    /// The linked group addresses the keyring holds a group key for; the model
    /// marks them `secure`.
    pub secure_groups: BTreeSet<GroupAddress>,
    /// Whether [`secure_objects`](Self::secure_objects) came from the device's
    /// PID 61 flags (`true`) or from the keyring alone (`false`).
    pub from_device_flags: bool,
    /// Objects the device flags secured that link no keyed group address: the
    /// keyring is older than the device's last download, or lacks a key.
    pub flagged_without_key: Vec<u16>,
    /// Objects linked to a keyed group address that the device does not flag:
    /// the keyring is newer than the device's last download.
    pub keyed_not_flagged: Vec<u16>,
}

/// Derives the [`SecureAdoption`] of a device from its links, the keyring's
/// group keys and, when read, the objects the device flags secured (PID 61).
///
/// ETS secures a group object when it links a keyed group address (issue
/// #156), so the keyring predicts the flags; the device's flags are what it
/// actually enforces and win when present. Disagreements are listed, not
/// resolved.
pub fn derive_secure_adoption(
    links: &[Link],
    group_keys: &HashMap<GroupAddress, Key16>,
    device_flags: Option<&BTreeSet<u16>>,
) -> SecureAdoption {
    let mut keyed_objects = BTreeSet::new();
    let mut secure_groups = BTreeSet::new();
    for link in links {
        for ga in link.send.iter().chain(link.listen.iter()) {
            if group_keys.contains_key(ga) {
                secure_groups.insert(*ga);
                keyed_objects.insert(link.object);
            }
        }
    }
    match device_flags {
        Some(flags) => {
            let linked: BTreeSet<u16> = links.iter().map(|l| l.object).collect();
            SecureAdoption {
                secure_objects: flags.clone(),
                secure_groups,
                from_device_flags: true,
                flagged_without_key: flags
                    .iter()
                    .filter(|o| linked.contains(o) && !keyed_objects.contains(o))
                    .copied()
                    .collect(),
                keyed_not_flagged: keyed_objects.difference(flags).copied().collect(),
            }
        }
        None => SecureAdoption {
            secure_objects: keyed_objects,
            secure_groups,
            from_device_flags: false,
            flagged_without_key: Vec::new(),
            keyed_not_flagged: Vec::new(),
        },
    }
}

/// The device-generated security facts of an adopted device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecureDeviceFacts {
    /// The keyring's `SequenceNumber` for the device, if it has one.
    pub sequence_number: Option<u64>,
    /// The security individual address table read from PID 54 (empty when it
    /// was not read or is empty).
    pub senders: Vec<SecureSender>,
}

/// Records an adopted, Data Secure-activated device in `model`.
///
/// - the device file's `[security]` gets `activated = true` and
///   `secure_commissioning = true` (ETS commissioned it with a tool key);
/// - the lock gets `secure_capable = true`, the keyring sequence and the sender
///   table (`secure_senders`), which a later secured download writes back;
/// - every object in [`SecureAdoption::secure_objects`] is marked `secure`
///   (an object the model does not know yet is left alone: its flags come from
///   the product data or the caller's placeholder);
/// - every group in [`SecureAdoption::secure_groups`] is marked `secure`,
///   created with `placeholder_name` when the model lacks it. A group already
///   marked `secure` is never cleared.
///
/// Does nothing when `device` is not in the model.
pub fn apply_secure_adoption(
    model: &mut Model,
    device: IndividualAddress,
    adoption: &SecureAdoption,
    facts: &SecureDeviceFacts,
    placeholder_name: impl Fn(GroupAddress) -> String,
) {
    let Some(loaded) = model.devices.get_mut(&device) else {
        return;
    };
    let dev = &mut loaded.device;
    let previous = dev.security.clone().unwrap_or_default();
    dev.security = Some(DeviceSecurity {
        secure_capable: true,
        activated: true,
        secure_commissioning: true,
        has_fdsk_certificate: previous.has_fdsk_certificate,
        sequence_number: facts.sequence_number.or(previous.sequence_number),
        secure_senders: facts.senders.clone(),
    });
    for number in &adoption.secure_objects {
        if let Some(co) = dev.com_objects.get_mut(number) {
            co.secure = true;
        }
    }
    for ga in &adoption.secure_groups {
        model
            .groups
            .groups
            .entry(*ga)
            .or_insert_with(|| Group {
                name: placeholder_name(*ga),
                ..Group::default()
            })
            .secure = true;
    }
}

/// A placeholder com-object for a linked object the model has no product data
/// for: `C` plus `W` for a listening object (`T` for a sending one), so the
/// links validate, size unknown. The real flags come with the product data.
pub fn placeholder_object(link: &Link) -> ComObject {
    let mut flags = Flags::COMMUNICATION;
    if link.send.is_some() {
        flags |= Flags::TRANSMIT;
    }
    if !link.listen.is_empty() || link.send.is_none() {
        flags |= Flags::WRITE;
    }
    ComObject {
        size: Some("unknown".to_string()),
        flags,
        ..ComObject::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ga(s: &str) -> Result<GroupAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn keys(gas: &[&str]) -> Result<HashMap<GroupAddress, Key16>, Box<dyn std::error::Error>> {
        let mut out = HashMap::new();
        for g in gas {
            out.insert(ga(g)?, Key16::new([7; 16]));
        }
        Ok(out)
    }

    #[test]
    fn test_links_from_tables_sends_on_the_first_address_of_a_transmitting_object() -> TestResult
    {
        let resolved = vec![
            (1, ga("1/2/3")?),
            (2, ga("1/2/4")?),
            (1, ga("1/2/5")?),
            (2, ga("1/2/1")?),
            (3, ga("1/2/6")?),
            (1, ga("1/2/3")?),
        ];
        let flags = |o: u16| match o {
            1 => Some(Flags::COMMUNICATION | Flags::TRANSMIT | Flags::WRITE),
            2 => Some(Flags::COMMUNICATION | Flags::WRITE),
            _ => None,
        };
        let links = links_from_tables(&resolved, flags);
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].object, 1);
        assert_eq!(links[0].send, Some(ga("1/2/3")?));
        assert_eq!(links[0].listen, vec![ga("1/2/5")?]);
        assert_eq!(links[1].send, None);
        assert_eq!(links[1].listen, vec![ga("1/2/4")?, ga("1/2/1")?]);
        // Unknown flags: listen only.
        assert_eq!(links[2].send, None);
        assert_eq!(links[2].listen, vec![ga("1/2/6")?]);
        Ok(())
    }

    #[test]
    fn test_derive_secure_adoption_prefers_the_device_flags_and_lists_disagreements()
    -> TestResult {
        let links = vec![
            Link {
                object: 1,
                name: None,
                send: None,
                listen: vec![ga("1/2/3")?],
            },
            Link {
                object: 2,
                name: None,
                send: Some(ga("1/2/4")?),
                listen: vec![],
            },
            Link {
                object: 3,
                name: None,
                send: None,
                listen: vec![ga("1/2/5")?],
            },
        ];
        let keys = keys(&["1/2/3", "1/2/5", "9/7/9"])?;
        // Keyring only.
        let a = derive_secure_adoption(&links, &keys, None);
        assert_eq!(a.secure_objects, BTreeSet::from([1, 3]));
        assert_eq!(a.secure_groups, BTreeSet::from([ga("1/2/3")?, ga("1/2/5")?]));
        assert!(!a.from_device_flags);
        // The device flags 1 and 2: 2 links no keyed GA, 3 is keyed but not
        // flagged.
        let flags = BTreeSet::from([1, 2]);
        let a = derive_secure_adoption(&links, &keys, Some(&flags));
        assert_eq!(a.secure_objects, flags);
        assert!(a.from_device_flags);
        assert_eq!(a.flagged_without_key, vec![2]);
        assert_eq!(a.keyed_not_flagged, vec![3]);
        Ok(())
    }

    #[test]
    fn test_apply_secure_adoption_writes_intent_lock_facts_and_flags() -> TestResult {
        let address: IndividualAddress = "1.1.12".parse()?;
        let mut device = bussard_model::schema::Device {
            address,
            name: "d".to_string(),
            description: None,
            location: None,
            replaced: None,
            product: None,
            channels: Default::default(),
            parameters: Default::default(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            security: None,
            application_override: None,
            lock: Default::default(),
        };
        device.com_objects.insert(1, ComObject::default());
        let mut model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        model.groups.groups.insert(
            ga("1/2/3")?,
            Group {
                name: "existing".to_string(),
                ..Group::default()
            },
        );
        model.devices.insert(
            address,
            bussard_model::LoadedDevice {
                device,
                file_stem: "1.1.12".to_string(),
            },
        );
        let adoption = SecureAdoption {
            secure_objects: BTreeSet::from([1, 7]),
            secure_groups: BTreeSet::from([ga("1/2/3")?, ga("1/2/9")?]),
            ..SecureAdoption::default()
        };
        let facts = SecureDeviceFacts {
            sequence_number: Some(42),
            senders: vec![SecureSender {
                address: "1.1.5".parse()?,
                sequence: 9,
            }],
        };
        apply_secure_adoption(&mut model, address, &adoption, &facts, |g| {
            format!("GA {g} (adopted)")
        });
        let dev = &model.devices.get(&address).ok_or("device")?.device;
        let sec = dev.security.as_ref().ok_or("security")?;
        assert!(sec.activated && sec.secure_commissioning && sec.secure_capable);
        assert_eq!(sec.sequence_number, Some(42));
        assert_eq!(sec.secure_senders, facts.senders);
        assert!(dev.com_objects.get(&1).is_some_and(|c| c.secure));
        assert!(!dev.com_objects.contains_key(&7), "no object invented");
        let g = model.groups.groups.get(&ga("1/2/3")?).ok_or("1/2/3")?;
        assert!(g.secure && g.name == "existing");
        let g = model.groups.groups.get(&ga("1/2/9")?).ok_or("1/2/9")?;
        assert!(g.secure && g.name == "GA 1/2/9 (adopted)");
        Ok(())
    }

    #[test]
    fn test_placeholder_object_validates_its_link() -> TestResult {
        let send = Link {
            object: 1,
            name: None,
            send: Some(ga("1/2/3")?),
            listen: vec![],
        };
        let flags = placeholder_object(&send).flags;
        assert!(flags.contains(Flags::TRANSMIT) && !flags.contains(Flags::WRITE));
        let listen = Link {
            object: 2,
            name: None,
            send: None,
            listen: vec![ga("1/2/4")?],
        };
        let flags = placeholder_object(&listen).flags;
        assert!(flags.contains(Flags::WRITE) && !flags.contains(Flags::TRANSMIT));
        Ok(())
    }
}
