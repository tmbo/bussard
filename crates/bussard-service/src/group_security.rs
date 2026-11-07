//! Switching KNX Data Secure on or off for one group address (issue #331).
//!
//! bussard treats a group address as secured when any of three signals says
//! so: the key store (`bussard.keys`) holds its group key, `groups.toml`
//! marks it `secure`, or a com-object linked to it is `secure` in the lock.
//! The security-object builder secures a group address when the key store
//! has a key OR the model flag is set
//! ([`bussard_download::security_inputs_for`]), so all three move together:
//!
//! - [`edit_model`] sets or clears the group's flag and the flag of every
//!   com-object linked to it on every device;
//! - [`apply_group_key`] removes the group key from the key store, or adds
//!   one: the key it already had, else a new random 128-bit key, as ETS 6
//!   creates one when a group address's security is switched on;
//! - [`keep_keystore`] copies the encrypted store into the history snapshot
//!   taken before the edit, and [`restore_group_keys`] gives a group address
//!   its key back (or takes it away) when `undo` restores a snapshot whose
//!   `secure` flag differs, so one undo restores all three signals.
//!
//! The devices learn the change through `plan` and `apply` (or `flash`): the
//! security object's group key table and group-object flags are rewritten
//! (`crate::security_change`). Every keyring user outside bussard (Home
//! Assistant, another ETS) needs a new `bussard keys export`
//! ([`export_note`]).
//!
//! Nothing here prints a key: messages name addresses and object numbers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_project::KeyStore;
use bussard_project::keystore::KeyStoreError;
use bussard_secure::Key16;

use crate::ServiceError;

/// The file name of the key store copy a history snapshot keeps.
pub const SNAPSHOT_KEYSTORE: &str = bussard_project::keystore::KEYSTORE_FILE;

/// What [`edit_model`] changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSecurityEdit {
    /// The group address.
    pub ga: GroupAddress,
    /// The new state.
    pub secure: bool,
    /// Every device linked to the group address, with its linked objects,
    /// ascending: the devices whose security object changes.
    pub devices: BTreeMap<IndividualAddress, BTreeSet<u16>>,
}

impl GroupSecurityEdit {
    /// The Secure devices `plan`/`apply` must reach: every linked device the
    /// model records as security-activated.
    pub fn secure_devices(&self, model: &Model) -> Vec<IndividualAddress> {
        self.devices
            .keys()
            .copied()
            .filter(|ia| device_activated(model, *ia))
            .collect()
    }
}

/// Whether the model records `ia` as KNX Data Secure activated.
fn device_activated(model: &Model, ia: IndividualAddress) -> bool {
    model
        .devices
        .get(&ia)
        .and_then(|d| d.device.security.as_ref())
        .is_some_and(|s| s.activated)
}

/// Whether the model records `ia` as able to run KNX Data Secure.
fn device_secure_capable(model: &Model, ia: IndividualAddress) -> bool {
    model
        .devices
        .get(&ia)
        .and_then(|d| d.device.security.as_ref())
        .is_some_and(|s| s.activated || s.secure_capable || s.secure_commissioning)
}

/// The devices and objects linked to `ga` (send or listen).
fn linked_objects(model: &Model, ga: GroupAddress) -> BTreeMap<IndividualAddress, BTreeSet<u16>> {
    let mut out: BTreeMap<IndividualAddress, BTreeSet<u16>> = BTreeMap::new();
    for (ia, links) in &model.links.links {
        for link in links {
            if link.send == Some(ga) || link.listen.contains(&ga) {
                out.entry(*ia).or_default().insert(link.object);
            }
        }
    }
    out
}

/// Sets (`secure = true`) or clears the KNX Data Secure flag of `ga` in
/// `model`: the group's `secure` and the `secure` of every com-object linked
/// to it on every device.
///
/// Refused, with the reason, when:
///
/// - `ga` is not in `groups.toml`;
/// - clearing: a linked object also links another group address that stays
///   secured (the security flag is per object, so the object cannot run one
///   group address plain and another secured);
/// - setting: a linked device is not Data Secure capable in the model (a
///   plain device would no longer understand the group address; ETS refuses
///   this too).
///
/// # Errors
///
/// The refusal, in words for the human.
pub fn edit_model(
    model: &mut Model,
    ga: GroupAddress,
    secure: bool,
) -> Result<GroupSecurityEdit, String> {
    if !model.groups.groups.contains_key(&ga) {
        return Err(format!(
            "{ga} is not in groups.toml; create it first (a new group address needs a name)"
        ));
    }
    let devices = linked_objects(model, ga);
    if secure {
        let plain: Vec<String> = devices
            .keys()
            .filter(|ia| !device_secure_capable(model, **ia))
            .map(ToString::to_string)
            .collect();
        if !plain.is_empty() {
            return Err(format!(
                "{ga} cannot run secured: {} {} not KNX Data Secure capable in your project, and a \
                 plain device cannot send or receive a secured group address (ETS refuses this \
                 too)",
                plain.join(", "),
                if plain.len() == 1 { "is" } else { "are" }
            ));
        }
    } else {
        let mut conflicts = Vec::new();
        for (ia, objects) in &devices {
            for link in model.links.links.get(ia).into_iter().flatten() {
                if !objects.contains(&link.object) {
                    continue;
                }
                let others: Vec<String> = link
                    .send
                    .iter()
                    .chain(link.listen.iter())
                    .filter(|other| **other != ga)
                    .filter(|other| model.groups.groups.get(other).is_some_and(|g| g.secure))
                    .map(ToString::to_string)
                    .collect();
                if !others.is_empty() {
                    conflicts.push(format!(
                        "object {} on {ia} also links the secured {}",
                        link.object,
                        others.join(", ")
                    ));
                }
            }
        }
        if !conflicts.is_empty() {
            return Err(format!(
                "{ga} cannot run plain while a linked object stays secured: {}. A group \
                 object's security flag covers all its group addresses; switch those off too, or \
                 unlink {ga} from the object first",
                conflicts.join("; ")
            ));
        }
    }
    if let Some(group) = model.groups.groups.get_mut(&ga) {
        group.secure = secure;
    }
    for (ia, objects) in &devices {
        if let Some(loaded) = model.devices.get_mut(ia) {
            for number in objects {
                if let Some(co) = loaded.device.com_objects.get_mut(number) {
                    co.secure = secure;
                }
            }
        }
    }
    Ok(GroupSecurityEdit {
        ga,
        secure,
        devices,
    })
}

/// What [`apply_group_key`] did to the key store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKeyAction {
    /// The group key was removed (and the group address from every
    /// interface entry that listed it).
    Removed,
    /// The store held no key for the group address.
    NotPresent,
    /// A new random group key was generated and stored.
    Generated,
    /// The store already held a key; it is kept.
    Kept,
}

impl GroupKeyAction {
    /// Whether the store changed.
    pub fn changed(self) -> bool {
        matches!(self, GroupKeyAction::Removed | GroupKeyAction::Generated)
    }

    /// `removed`, `not_present`, `generated`, `kept`, for a JSON field.
    pub fn label(self) -> &'static str {
        match self {
            GroupKeyAction::Removed => "removed",
            GroupKeyAction::NotPresent => "not_present",
            GroupKeyAction::Generated => "generated",
            GroupKeyAction::Kept => "kept",
        }
    }

    /// One sentence for the human, naming the group address only.
    pub fn sentence(self, ga: GroupAddress) -> String {
        match self {
            GroupKeyAction::Removed => {
                format!("The key store no longer holds a group key for {ga}.")
            }
            GroupKeyAction::NotPresent => {
                format!("The key store held no group key for {ga}; nothing to remove there.")
            }
            GroupKeyAction::Generated => format!(
                "The key store holds a new random group key for {ga} (generated as ETS does when \
                 a group address's security is switched on)."
            ),
            GroupKeyAction::Kept => {
                format!("The key store keeps the group key it already held for {ga}.")
            }
        }
    }
}

/// Removes (`secure = false`) or adds the group key of `ga` in `store`.
///
/// Removing also drops `ga` from every interface entry that lists it (ETS
/// lists only secured group addresses there). Adding keeps an existing key
/// and otherwise generates a random 128-bit key from the operating system's
/// random source, which is what ETS 6 does when a group address's security is
/// switched on.
///
/// # Errors
///
/// The random source failed.
pub fn apply_group_key(
    store: &mut KeyStore,
    ga: GroupAddress,
    secure: bool,
) -> Result<GroupKeyAction, bussard_secure::CryptoError> {
    if secure {
        if store.group_keys.contains_key(&ga) {
            return Ok(GroupKeyAction::Kept);
        }
        let bytes: [u8; 16] = bussard_secure::random_bytes()?;
        store.group_keys.insert(ga, Key16::new(bytes));
        return Ok(GroupKeyAction::Generated);
    }
    let removed = store.group_keys.remove(&ga).is_some();
    let mut listed = false;
    for interface in &mut store.interfaces {
        let before = interface.gas.len();
        interface.gas.retain(|(g, _)| *g != ga);
        listed |= interface.gas.len() != before;
    }
    Ok(if removed || listed {
        GroupKeyAction::Removed
    } else {
        GroupKeyAction::NotPresent
    })
}

/// The note every result of a security change carries: Home Assistant and
/// every other keyring user need the new export.
pub fn export_note(ga: GroupAddress, secure: bool) -> String {
    if secure {
        format!(
            "{ga} now has a group key only bussard knows. Home Assistant and every other \
             keyring user (ETS, a visualisation) need the new key: run `bussard keys export \
             <file.knxkeys>` and load that export there, or they cannot read or send {ga} once \
             the devices run it secured."
        )
    } else {
        format!(
            "Home Assistant and every other keyring user (ETS, a visualisation) still hold the \
             group key of {ga} and keep sending it secured, which the devices drop once they run \
             {ga} plain: run `bussard keys export <file.knxkeys>` and load that export there \
             (it no longer carries the key)."
        )
    }
}

/// The key store password is not set.
fn missing_password() -> ServiceError {
    ServiceError::Refused(format!(
        "the key store password must be set in {} to change a group key",
        crate::secure::KEYRING_PASSWORD_ENV
    ))
}

/// The store at `path` did not load or save.
fn store_error(path: &Path, source: KeyStoreError) -> ServiceError {
    ServiceError::because(format!("the key store {}", path.display()), source)
}

/// Loads the key store of `dir` with `password`.
///
/// # Errors
///
/// No password, no store, or a store that does not load.
pub fn load_store(dir: &Path, password: Option<&str>) -> Result<KeyStore, ServiceError> {
    let password = password.ok_or_else(missing_password)?;
    let path = KeyStore::path(dir);
    match KeyStore::load(dir, password) {
        Ok(Some(store)) => Ok(store),
        Ok(None) => Err(ServiceError::Refused(format!(
            "there is no key store {}: import the ETS keyring with `bussard keys import <file>` first",
            path.display()
        ))),
        Err(source) => Err(store_error(&path, source)),
    }
}

/// Saves `store` into `dir`.
///
/// # Errors
///
/// The store does not save.
pub fn save_store(dir: &Path, store: &KeyStore, password: &str) -> Result<(), ServiceError> {
    store
        .save(dir, password)
        .map(|_| ())
        .map_err(|source| store_error(&KeyStore::path(dir), source))
}

/// Copies the key store of `dir` (encrypted, as it is git-tracked) into the
/// history snapshot directory `snapshot_dir`, so an undo can give a group
/// address its key back. Returns whether there was a store to copy.
///
/// # Errors
///
/// The copy failed.
pub fn keep_keystore(dir: &Path, snapshot_dir: &Path) -> Result<bool, ServiceError> {
    let from = KeyStore::path(dir);
    if !from.is_file() {
        return Ok(false);
    }
    let to = snapshot_dir.join(SNAPSHOT_KEYSTORE);
    std::fs::copy(&from, &to).map_err(|source| {
        ServiceError::because(format!("copying the key store to {}", to.display()), source)
    })?;
    Ok(true)
}

/// The group addresses whose `secure` flag differs between `before` and
/// `after`, with the state in `after`.
pub fn security_changes(before: &Model, after: &Model) -> BTreeMap<GroupAddress, bool> {
    after
        .groups
        .groups
        .iter()
        .filter(|(ga, g)| before.groups.groups.get(ga).map(|b| b.secure) != Some(g.secure))
        .map(|(ga, g)| (*ga, g.secure))
        .collect()
}

/// After an undo restored the model of `snapshot_dir` (`before` is the model
/// the undo replaced, `after` the restored one): makes the key store follow
/// every group address whose `secure` flag the undo changed. A group address
/// that runs secured again gets the key the snapshot's key store copy held
/// (and its interface entries); one that runs plain again loses its key.
/// `undo_snapshot_dir` (the snapshot the undo took of the replaced state)
/// receives a copy of the store first, so the undo itself can be undone.
///
/// Returns one sentence per group address, naming addresses only. Nothing is
/// written when no `secure` flag changed.
///
/// # Errors
///
/// No password, no store, a store that does not load or save.
pub fn restore_group_keys(
    dir: &Path,
    snapshot_dir: &Path,
    undo_snapshot_dir: Option<&Path>,
    before: &Model,
    after: &Model,
    password: Option<&str>,
) -> Result<Vec<String>, ServiceError> {
    let changes = security_changes(before, after);
    if changes.is_empty() {
        return Ok(Vec::new());
    }
    let mut store = load_store(dir, password)?;
    let password = password.ok_or_else(missing_password)?;
    if let Some(undo_dir) = undo_snapshot_dir {
        keep_keystore(dir, undo_dir)?;
    }
    let copy_path = snapshot_dir.join(SNAPSHOT_KEYSTORE);
    let copy = if copy_path.is_file() {
        let xml = std::fs::read_to_string(&copy_path).map_err(|source| {
            ServiceError::because(format!("reading {}", copy_path.display()), source)
        })?;
        Some(KeyStore::parse(&xml, password).map_err(|source| store_error(&copy_path, source))?)
    } else {
        None
    };
    let mut notes = Vec::new();
    for (ga, secure) in changes {
        if !secure {
            let action = apply_group_key(&mut store, ga, false)
                .map_err(|e| ServiceError::because("generating a group key", e))?;
            notes.push(action.sentence(ga));
            continue;
        }
        let Some(key) = copy.as_ref().and_then(|c| c.group_key(ga)).cloned() else {
            notes.push(format!(
                "{ga} runs secured again, but the snapshot keeps no key store copy with its key; \
                 the key store is unchanged for {ga}. Re-import the keyring that has it, or set \
                 it secure again to generate a new one."
            ));
            continue;
        };
        store.group_keys.insert(ga, key);
        // The interface entries that listed the group address get it back.
        if let Some(copy) = &copy {
            for old in &copy.interfaces {
                let Some(entry) = old.gas.iter().find(|(g, _)| *g == ga) else {
                    continue;
                };
                if let Some(interface) = store
                    .interfaces
                    .iter_mut()
                    .find(|i| i.ia == old.ia && i.interface_type == old.interface_type)
                    && !interface.gas.iter().any(|(g, _)| *g == ga)
                {
                    interface.gas.push(entry.clone());
                    interface.gas.sort_by_key(|(g, _)| *g);
                }
            }
        }
        notes.push(format!(
            "The key store holds the group key of {ga} again (from the snapshot's key store copy)."
        ));
    }
    save_store(dir, &store, password)?;
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::LoadedDevice;
    use bussard_model::schema::{
        BussardConfig, ComObject, Device, DeviceSecurity, Group, Groups, Link, Links,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ga(s: &str) -> Result<GroupAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn link(object: u16, send: Option<GroupAddress>, listen: Vec<GroupAddress>) -> Link {
        Link {
            object,
            name: None,
            send,
            listen,
        }
    }

    /// 1.1.5 (activated) listens to the secured 1/0/4 with object 12 and to
    /// the secured 1/0/9 with object 20.
    fn model() -> Result<Model, Box<dyn std::error::Error>> {
        let mut groups = Groups::default();
        for (address, name) in [("1/0/4", "Kitchen light"), ("1/0/9", "Hall light")] {
            groups.groups.insert(
                ga(address)?,
                Group {
                    name: name.to_string(),
                    secure: true,
                    ..Default::default()
                },
            );
        }
        let mut links = Links::default();
        links.links.insert(
            ia("1.1.5")?,
            vec![
                link(12, None, vec![ga("1/0/4")?]),
                link(20, None, vec![ga("1/0/9")?]),
            ],
        );
        let mut com_objects = BTreeMap::new();
        for number in [12u16, 20] {
            com_objects.insert(
                number,
                ComObject {
                    secure: true,
                    ..ComObject::default()
                },
            );
        }
        let device = Device {
            address: ia("1.1.5")?,
            name: "Kitchen actuator".to_string(),
            description: None,
            location: None,
            product: None,
            channels: Default::default(),
            parameters: Default::default(),
            module_bases: Default::default(),
            com_objects,
            security: Some(DeviceSecurity {
                activated: true,
                ..Default::default()
            }),
            replaced: None,
            application_override: None,
            knxnet: None,
            lock: Default::default(),
        };
        let mut devices = BTreeMap::new();
        devices.insert(
            device.address,
            LoadedDevice {
                device,
                file_stem: "1.1.5".to_string(),
            },
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups,
            links,
            devices,
        })
    }

    #[test]
    fn test_edit_model_clears_the_group_and_every_linked_object() -> TestResult {
        let mut model = model()?;
        let edit = edit_model(&mut model, ga("1/0/4")?, false)?;
        assert!(!model.groups.groups[&ga("1/0/4")?].secure);
        assert!(model.groups.groups[&ga("1/0/9")?].secure, "1/0/9 untouched");
        let device = &model.devices[&ia("1.1.5")?].device;
        assert!(!device.com_objects[&12].secure);
        assert!(device.com_objects[&20].secure, "object 20 untouched");
        assert_eq!(
            edit.devices,
            BTreeMap::from([(ia("1.1.5")?, BTreeSet::from([12]))])
        );
        assert_eq!(edit.secure_devices(&model), vec![ia("1.1.5")?]);
        Ok(())
    }

    #[test]
    fn test_edit_model_refuses_an_object_that_stays_secured() -> TestResult {
        let mut model = model()?;
        if let Some(links) = model.links.links.get_mut(&ia("1.1.5")?) {
            links[0].listen.push(ga("1/0/9")?);
        }
        let err = edit_model(&mut model, ga("1/0/4")?, false)
            .err()
            .ok_or("expected a refusal")?;
        assert!(
            err.contains("object 12 on 1.1.5 also links the secured 1/0/9"),
            "{err}"
        );
        assert!(model.groups.groups[&ga("1/0/4")?].secure, "nothing changed");
        Ok(())
    }

    #[test]
    fn test_edit_model_refuses_to_secure_a_plain_device() -> TestResult {
        let mut model = model()?;
        model
            .links
            .links
            .insert(ia("1.1.40")?, vec![link(1, Some(ga("1/0/4")?), Vec::new())]);
        edit_model(&mut model, ga("1/0/4")?, false)?;
        let err = edit_model(&mut model, ga("1/0/4")?, true)
            .err()
            .ok_or("expected a refusal")?;
        assert!(
            err.contains("1.1.40 is not KNX Data Secure capable"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn test_apply_group_key_removes_and_generates() -> TestResult {
        let mut store = KeyStore::new("Synthetic");
        store
            .group_keys
            .insert(ga("1/0/4")?, Key16::new([0x42; 16]));
        assert_eq!(
            apply_group_key(&mut store, ga("1/0/4")?, false)?,
            GroupKeyAction::Removed
        );
        assert!(store.group_key(ga("1/0/4")?).is_none());
        assert_eq!(
            apply_group_key(&mut store, ga("1/0/4")?, false)?,
            GroupKeyAction::NotPresent
        );
        assert_eq!(
            apply_group_key(&mut store, ga("1/0/4")?, true)?,
            GroupKeyAction::Generated
        );
        let generated = store.group_key(ga("1/0/4")?).cloned().ok_or("no key")?;
        assert_ne!(generated.bytes(), &[0x42; 16], "a new key, not the old one");
        assert_eq!(
            apply_group_key(&mut store, ga("1/0/4")?, true)?,
            GroupKeyAction::Kept
        );
        assert_eq!(store.group_key(ga("1/0/4")?), Some(&generated));
        Ok(())
    }

    #[test]
    fn test_security_changes_lists_flipped_groups() -> TestResult {
        let before = model()?;
        let mut after = before.clone();
        edit_model(&mut after, ga("1/0/4")?, false)?;
        assert_eq!(
            security_changes(&before, &after),
            BTreeMap::from([(ga("1/0/4")?, false)])
        );
        assert_eq!(
            security_changes(&after, &before),
            BTreeMap::from([(ga("1/0/4")?, true)])
        );
        Ok(())
    }

    #[test]
    fn test_keystore_round_trip_remove_export_reimport_and_undo() -> TestResult {
        const PASSWORD: &str = "synthetic-pw";
        let dir = std::env::temp_dir().join(format!(
            "bussard-group-security-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let snapshot = dir.join("snapshot");
        let undo_snapshot = dir.join("undo-snapshot");
        std::fs::create_dir_all(&snapshot)?;
        std::fs::create_dir_all(&undo_snapshot)?;
        let mut store = KeyStore::new("Synthetic");
        store
            .group_keys
            .insert(ga("1/0/4")?, Key16::new([0x42; 16]));
        store
            .group_keys
            .insert(ga("1/0/9")?, Key16::new([0x43; 16]));
        save_store(&dir, &store, PASSWORD)?;

        // The edit: the snapshot keeps the store, then the key goes.
        assert!(keep_keystore(&dir, &snapshot)?);
        let mut store = load_store(&dir, Some(PASSWORD))?;
        assert_eq!(
            apply_group_key(&mut store, ga("1/0/4")?, false)?,
            GroupKeyAction::Removed
        );
        save_store(&dir, &store, PASSWORD)?;

        // The export carries no key for 1/0/4; re-importing it keeps it out.
        let export = load_store(&dir, Some(PASSWORD))?.export_knxkeys(PASSWORD)?;
        assert_eq!(export.group_keys, 1);
        let keyring = bussard_project::parse_keyring(&export.xml, PASSWORD)?;
        assert!(!keyring.group_keys.contains_key(&ga("1/0/4")?));
        assert!(keyring.group_keys.contains_key(&ga("1/0/9")?));
        let mut store = load_store(&dir, Some(PASSWORD))?;
        store.merge_keyring(&keyring);
        assert!(store.group_key(ga("1/0/4")?).is_none());
        save_store(&dir, &store, PASSWORD)?;

        // The undo: the model runs 1/0/4 secured again, and the key store
        // gets the very key back from the snapshot's copy.
        let secured = model()?;
        let mut plain = secured.clone();
        edit_model(&mut plain, ga("1/0/4")?, false)?;
        let notes = restore_group_keys(
            &dir,
            &snapshot,
            Some(&undo_snapshot),
            &plain,
            &secured,
            Some(PASSWORD),
        )?;
        assert_eq!(notes.len(), 1, "{notes:?}");
        let store = load_store(&dir, Some(PASSWORD))?;
        assert_eq!(
            store.group_key(ga("1/0/4")?).map(|k| *k.bytes()),
            Some([0x42; 16])
        );
        assert!(undo_snapshot.join(SNAPSHOT_KEYSTORE).is_file());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
