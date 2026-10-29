//! The plan side of a group address that leaves or joins KNX Data Secure
//! (issue #331): what a Secure device's security object must change so its
//! group key table (PID 53) and group-object security flags (PID 61) match
//! the model and the key store again.
//!
//! The evidence is the device itself: `plan` and `apply` read PID 61 over the
//! secured session ([`bussard_download::read_security_flags`]) and compare it
//! with the flags the model asks for ([`bussard_download::SecurityInputs`]).
//! PID 53 is write-only, so the group key side is derived: a group address
//! the key store no longer keys, linked to an object that loses its flag, is
//! the key that leaves the table, and a keyed group address linked to an
//! object that gains its flag is the key that joins it. ETS secures a group
//! object exactly when it links a keyed group address (dev/knx-secure-spec.md
//! §11), so the two sides move together.
//!
//! The change is one plan line naming the group addresses and the objects.
//! The write is the full security-object program of a secured table write
//! ([`bussard_download::program_security_object`]), the shape a full ETS
//! download writes. After a verified write, [`record_security_flags`] records
//! the flags in the lock's com-objects, as `admission::record_secure_senders`
//! records PID 54.
//!
//! The read budget (issue #336): PID 61 is the session's last read and a
//! device that does not answer it costs a full response timeout, so a plan
//! does not read it on every call. A plan's live read is cached in the
//! device facts ([`remember_flags`]); the next plan uses the cache only when
//! the model asks for exactly the flags it holds ([`unchanged_cached_flags`]),
//! that is when no security change is pending. A pending change, a missing
//! cache, `--refresh-facts`, every apply and every flash read the device;
//! an apply and a flash drop the cache ([`forget_flags`]) because they may
//! change the flags.
//!
//! Nothing here reads or prints key material: addresses and object numbers
//! only.

use std::collections::{BTreeMap, BTreeSet};

use bussard_download::{
    ChangeMark, ChangeSubject, DesiredTables, DevicePlan, PlanChange, PlanReport, SecurityInputs,
};
use bussard_model::{GroupAddress, IndividualAddress, Model};

/// One group address whose Data Secure state changes on a device, with the
/// device's group objects linked to it whose flag changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSecurityDelta {
    /// The group address.
    pub ga: GroupAddress,
    /// The group objects linked to it whose security flag changes, ascending.
    pub objects: Vec<u16>,
}

/// What a Secure device's security object must change (issue #331): the
/// group keys that leave or join its group key table and the group objects
/// whose security flag changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityObjectChange {
    /// The device.
    pub device: IndividualAddress,
    /// Group addresses that leave Data Secure on this device: their key
    /// leaves the group key table and their objects lose the flag.
    pub removed: Vec<GroupSecurityDelta>,
    /// Group addresses that join Data Secure on this device.
    pub added: Vec<GroupSecurityDelta>,
    /// Every group object whose flag is cleared (`0x03` to `0x00`),
    /// ascending.
    pub cleared: Vec<u16>,
    /// Every group object whose flag is set (`0x00` to `0x03`), ascending.
    pub set: Vec<u16>,
    /// The group-object flags as read from PID 61 (element 1 first), for the
    /// state hash.
    live_secured: Vec<u16>,
}

impl SecurityObjectChange {
    /// Compares the flags the device holds (`live`, PID 61 as read, element 1
    /// first) with the ones the model and the key store ask for (`inputs`,
    /// from [`bussard_download::security_inputs_for`] over `desired`).
    pub fn compare(
        device: IndividualAddress,
        desired: &DesiredTables,
        inputs: &SecurityInputs,
        live: &[u8],
    ) -> SecurityObjectChange {
        let live_secured: BTreeSet<u16> = live
            .iter()
            .enumerate()
            .filter(|(_, flag)| **flag != 0)
            .filter_map(|(i, _)| u16::try_from(i + 1).ok())
            .collect();
        let cleared: BTreeSet<u16> = live_secured
            .difference(&inputs.secure_objects)
            .copied()
            .collect();
        let set: BTreeSet<u16> = inputs
            .secure_objects
            .difference(&live_secured)
            .copied()
            .collect();
        // The objects each group address of the table being written links.
        let mut linked: BTreeMap<GroupAddress, BTreeSet<u16>> = BTreeMap::new();
        for &(tsap, asap) in &desired.associations {
            if let Some(ga) = usize::from(tsap)
                .checked_sub(1)
                .and_then(|i| desired.addresses.get(i))
            {
                linked.entry(*ga).or_default().insert(asap);
            }
        }
        let mut removed = Vec::new();
        let mut added = Vec::new();
        for (ga, objects) in &linked {
            let keyed = inputs.group_keys.contains_key(ga);
            let lost: Vec<u16> = objects.intersection(&cleared).copied().collect();
            let gained: Vec<u16> = objects.intersection(&set).copied().collect();
            if !keyed && !lost.is_empty() {
                removed.push(GroupSecurityDelta {
                    ga: *ga,
                    objects: lost,
                });
            }
            if keyed && !gained.is_empty() {
                added.push(GroupSecurityDelta {
                    ga: *ga,
                    objects: gained,
                });
            }
        }
        SecurityObjectChange {
            device,
            removed,
            added,
            cleared: cleared.into_iter().collect(),
            set: set.into_iter().collect(),
            live_secured: live_secured.into_iter().collect(),
        }
    }

    /// Whether the security object must be written for this change.
    pub fn changes(&self) -> bool {
        !self.cleared.is_empty() || !self.set.is_empty()
    }

    /// The plan line, or `None` when the flags already match:
    ///
    /// `- Data Secure off for 1/0/4 (Kitchen light): its group key leaves the
    /// group key table (PID 53) and object 12 loses its security flag (PID 61
    /// 0x03 to 0x00)`.
    pub fn change(&self, model: Option<&Model>) -> Option<PlanChange> {
        if !self.changes() {
            return None;
        }
        let label = |ga: GroupAddress| -> String {
            match model
                .and_then(|m| m.groups.groups.get(&ga))
                .map(|g| g.name.trim())
                .filter(|n| !n.is_empty())
            {
                Some(name) => format!("{ga} ({name})"),
                None => ga.to_string(),
            }
        };
        let mut parts = Vec::new();
        let mut attributed: BTreeSet<u16> = BTreeSet::new();
        for delta in &self.removed {
            attributed.extend(delta.objects.iter().copied());
            parts.push(format!(
                "Data Secure off for {}: its group key leaves the group key table (PID 53) and \
                 {} {} its security flag (PID 61 0x03 to 0x00)",
                label(delta.ga),
                objects_phrase(&delta.objects),
                if delta.objects.len() == 1 {
                    "loses"
                } else {
                    "lose"
                },
            ));
        }
        for delta in &self.added {
            attributed.extend(delta.objects.iter().copied());
            parts.push(format!(
                "Data Secure on for {}: its group key joins the group key table (PID 53) and \
                 {} {} the security flag (PID 61 0x00 to 0x03)",
                label(delta.ga),
                objects_phrase(&delta.objects),
                if delta.objects.len() == 1 {
                    "gets"
                } else {
                    "get"
                },
            ));
        }
        let other_cleared: Vec<u16> = self
            .cleared
            .iter()
            .copied()
            .filter(|o| !attributed.contains(o))
            .collect();
        if !other_cleared.is_empty() {
            parts.push(format!(
                "{} {} its security flag (PID 61 0x03 to 0x00; no secured group address links it \
                 in the model)",
                objects_phrase(&other_cleared),
                if other_cleared.len() == 1 {
                    "loses"
                } else {
                    "lose"
                },
            ));
        }
        let other_set: Vec<u16> = self
            .set
            .iter()
            .copied()
            .filter(|o| !attributed.contains(o))
            .collect();
        if !other_set.is_empty() {
            parts.push(format!(
                "{} {} the security flag (PID 61 0x00 to 0x03)",
                objects_phrase(&other_set),
                if other_set.len() == 1 { "gets" } else { "get" },
            ));
        }
        let mark = match (self.cleared.is_empty(), self.set.is_empty()) {
            (false, true) => ChangeMark::Removed,
            (true, false) => ChangeMark::Added,
            _ => ChangeMark::Changed,
        };
        Some(PlanChange {
            mark,
            subject: ChangeSubject::Security,
            channel: None,
            key: "security object".to_string(),
            object: None,
            sentence: format!("security object: {}", parts.join("; ")),
        })
    }

    /// Adds the change to `plan`: the line, and the writes (the security
    /// object, and the tables it is written inside of). Does nothing when the
    /// flags match. The state hash takes in the flags as read, so an approved
    /// plan is refused if PID 61 changes before the apply.
    pub fn add_to(&self, plan: &mut DevicePlan, report: &PlanReport, model: Option<&Model>) {
        let Some(change) = self.change(model) else {
            return;
        };
        plan.changes.insert(0, change);
        plan.writes.security_object = true;
        plan.writes
            .address_table
            .get_or_insert(report.resulting_address_count);
        plan.writes
            .association_table
            .get_or_insert(report.resulting_association_count);
        let live: Vec<String> = self.live_secured.iter().map(u16::to_string).collect();
        plan.state_hash = format!(
            "{}-pid61-{}",
            plan.state_hash,
            crate::admission::short_digest(&live.join(","))
        );
    }
}

/// The security-object change a full flash makes on a Secure device (issue
/// #331): the flags and group keys of `plan`'s security program (from
/// [`crate::flash::FlashInputs::add_security_steps`]) compared with the PID
/// 61 the pre-flight read (`live`). `links` are the device's model links,
/// which name the objects of each group address. `None` when the plan writes
/// no security program.
pub fn from_flash_plan(
    device: IndividualAddress,
    plan: &bussard_download::FlashPlan,
    links: &[bussard_model::schema::Link],
    live: &[u8],
) -> Option<SecurityObjectChange> {
    let mut inputs = SecurityInputs::default();
    let mut programmed = false;
    for step in &plan.steps {
        match step {
            bussard_download::FlashStep::SecurityGroupKeys { entries } => {
                programmed = true;
                for entry in entries {
                    inputs
                        .group_keys
                        .insert(entry.group_address, entry.key.clone());
                }
            }
            bussard_download::FlashStep::SecurityGoFlags { flags } => {
                programmed = true;
                inputs.secure_objects = flags
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| **f != 0)
                    .filter_map(|(i, _)| u16::try_from(i + 1).ok())
                    .collect();
            }
            _ => {}
        }
    }
    programmed.then(|| {
        let desired = bussard_download::compute_tables(links);
        SecurityObjectChange::compare(device, &desired, &inputs, live)
    })
}

/// The group objects a flash plan's security program flags secured, or
/// `None` when it writes no security program: what a verified flash records
/// with [`record_security_flags`].
pub fn flash_secured_objects(plan: &bussard_download::FlashPlan) -> Option<BTreeSet<u16>> {
    plan.steps.iter().find_map(|step| match step {
        bussard_download::FlashStep::SecurityGoFlags { flags } => Some(
            flags
                .iter()
                .enumerate()
                .filter(|(_, f)| **f != 0)
                .filter_map(|(i, _)| u16::try_from(i + 1).ok())
                .collect(),
        ),
        _ => None,
    })
}

/// `object 12`, `objects 12, 13`.
fn objects_phrase(objects: &[u16]) -> String {
    let list: Vec<String> = objects.iter().map(u16::to_string).collect();
    if objects.len() == 1 {
        format!("object {}", list.join(""))
    } else {
        format!("objects {}", list.join(", "))
    }
}

/// The PID 61 flags of `target` a previous plan read (issue #336), when they
/// show no change against what the model and the key store ask for
/// (`desired`, `inputs`): a plan then takes them as read and skips the PID
/// 61 read. `None`, so the device is read, when nothing is cached, the cache
/// is unreadable, `refresh` (`--refresh-facts`) is set, or the cached flags
/// differ from the model's (a security change is pending).
pub fn unchanged_cached_flags(
    dir: &std::path::Path,
    target: IndividualAddress,
    desired: &DesiredTables,
    inputs: &SecurityInputs,
    refresh: bool,
) -> Option<Vec<u8>> {
    if refresh {
        return None;
    }
    let record = bussard_model::facts::load_facts(dir, target).ok()??;
    let flags = from_hex(record.go_security_flags.as_deref()?)?;
    (!SecurityObjectChange::compare(target, desired, inputs, &flags).changes()).then_some(flags)
}

/// Caches the PID 61 flags a plan read live from `target` in its device
/// facts (issue #336). Nothing happens without a facts record (no session
/// established facts for the device); a write failure is logged, the cache
/// being optional.
pub fn remember_flags(dir: &std::path::Path, target: IndividualAddress, flags: &[u8]) {
    update_cached_flags(dir, target, Some(to_hex(flags)));
}

/// Drops the cached PID 61 flags of `target` (issue #336): an apply or a
/// flash may change them, so the next plan reads the device again.
pub fn forget_flags(dir: &std::path::Path, target: IndividualAddress) {
    update_cached_flags(dir, target, None);
}

/// Sets the cached flags of `target`'s facts to `value`, writing only on a
/// change.
fn update_cached_flags(dir: &std::path::Path, target: IndividualAddress, value: Option<String>) {
    let Ok(Some(mut record)) = bussard_model::facts::load_facts(dir, target) else {
        return;
    };
    if record.go_security_flags == value {
        return;
    }
    record.go_security_flags = value;
    if let Err(err) = bussard_model::facts::save_facts(dir, &record) {
        tracing::warn!("could not cache the PID 61 flags of {target}: {err}");
    }
}

/// The flags as hex, two digits per object.
fn to_hex(flags: &[u8]) -> String {
    flags.iter().map(|f| format!("{f:02X}")).collect()
}

/// The flags from [`to_hex`], or `None` for a malformed value.
fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|d| u8::from_str_radix(d, 16).ok())
        })
        .collect()
}

/// Why [`record_security_flags`] could not update the lock.
#[derive(Debug, thiserror::Error)]
pub enum RecordFlagsError {
    /// The model did not load.
    #[error("loading the model to record the security flags: {0}")]
    Load(#[from] bussard_model::LoadError),
    /// The model did not save.
    #[error("saving the security flags to bussard.lock: {0}")]
    Save(#[from] bussard_model::SaveError),
}

/// Records the group-object security flags a verified secured write put on
/// `device` (PID 61, `secured`: the objects flagged `0x03`) as the `secure`
/// flag of its linked com-objects in the lock (issue #331), the way
/// `admission::record_secure_senders` records PID 54. A linked object the
/// write left plain is recorded plain, a flagged one secured; an object the
/// model does not link keeps its flag.
///
/// Call it only after the write verified. Returns whether the lock changed; a
/// device the model does not know is left alone (`false`).
///
/// # Errors
///
/// The model does not load or save.
pub fn record_security_flags(
    dir: &std::path::Path,
    device: IndividualAddress,
    secured: &BTreeSet<u16>,
) -> Result<bool, RecordFlagsError> {
    let mut model = Model::load(dir)?;
    let linked: BTreeSet<u16> = model
        .links
        .links
        .get(&device)
        .into_iter()
        .flatten()
        .filter(|l| l.send.is_some() || !l.listen.is_empty())
        .map(|l| l.object)
        .collect();
    let Some(loaded) = model.devices.get_mut(&device) else {
        return Ok(false);
    };
    let mut changed = false;
    for (number, co) in loaded.device.com_objects.iter_mut() {
        if !linked.contains(number) {
            continue;
        }
        let flag = secured.contains(number);
        if co.secure != flag {
            co.secure = flag;
            changed = true;
        }
    }
    if changed {
        model.save(dir)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ga(s: &str) -> Result<GroupAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    /// 1.1.5 with 1/0/4 (object 12) and 1/0/5 (object 13), both secured on
    /// the device (flags of 16 objects).
    fn live_flags() -> Vec<u8> {
        let mut flags = vec![0u8; 16];
        flags[11] = 0x03;
        flags[12] = 0x03;
        flags
    }

    fn desired() -> Result<DesiredTables, Box<dyn std::error::Error>> {
        Ok(DesiredTables {
            addresses: vec![ga("1/0/4")?, ga("1/0/5")?],
            associations: vec![(1, 12), (2, 13)],
        })
    }

    #[test]
    fn test_compare_names_the_ga_that_leaves_data_secure() -> TestResult {
        let mut keys = HashMap::new();
        keys.insert(ga("1/0/5")?, bussard_secure::Key16::new([0x5A; 16]));
        let inputs = SecurityInputs {
            secure_objects: BTreeSet::from([13]),
            group_keys: keys,
            ..SecurityInputs::default()
        };
        let change =
            SecurityObjectChange::compare(ia("1.1.5")?, &desired()?, &inputs, &live_flags());
        assert!(change.changes());
        assert_eq!(change.cleared, vec![12]);
        assert!(change.set.is_empty());
        assert_eq!(
            change.removed,
            vec![GroupSecurityDelta {
                ga: ga("1/0/4")?,
                objects: vec![12]
            }]
        );
        let line = change.change(None).ok_or("no plan line")?;
        assert_eq!(line.mark, ChangeMark::Removed);
        assert_eq!(line.subject, ChangeSubject::Security);
        assert_eq!(
            line.line(),
            "- security object: Data Secure off for 1/0/4: its group key leaves the group key \
             table (PID 53) and object 12 loses its security flag (PID 61 0x03 to 0x00)"
        );
        Ok(())
    }

    #[test]
    fn test_compare_is_quiet_when_the_flags_match() -> TestResult {
        let mut keys = HashMap::new();
        keys.insert(ga("1/0/4")?, bussard_secure::Key16::new([0x11; 16]));
        keys.insert(ga("1/0/5")?, bussard_secure::Key16::new([0x22; 16]));
        let inputs = SecurityInputs {
            secure_objects: BTreeSet::from([12, 13]),
            group_keys: keys,
            ..SecurityInputs::default()
        };
        let change =
            SecurityObjectChange::compare(ia("1.1.5")?, &desired()?, &inputs, &live_flags());
        assert!(!change.changes());
        assert!(change.change(None).is_none());
        Ok(())
    }

    #[test]
    fn test_compare_names_the_ga_that_joins_data_secure() -> TestResult {
        let mut keys = HashMap::new();
        keys.insert(ga("1/0/4")?, bussard_secure::Key16::new([0x11; 16]));
        let inputs = SecurityInputs {
            secure_objects: BTreeSet::from([12]),
            group_keys: keys,
            ..SecurityInputs::default()
        };
        let change = SecurityObjectChange::compare(ia("1.1.5")?, &desired()?, &inputs, &[0u8; 16]);
        assert_eq!(change.set, vec![12]);
        let line = change.change(None).ok_or("no plan line")?;
        assert_eq!(line.mark, ChangeMark::Added);
        assert!(
            line.sentence.contains("Data Secure on for 1/0/4"),
            "{}",
            line.sentence
        );
        Ok(())
    }

    #[test]
    fn test_add_to_forces_the_table_write_and_binds_the_flags() -> TestResult {
        let inputs = SecurityInputs::default();
        let change =
            SecurityObjectChange::compare(ia("1.1.5")?, &desired()?, &inputs, &live_flags());
        let mut plan = DevicePlan {
            address: "1.1.5".to_string(),
            name: String::new(),
            gateway: String::new(),
            changes: Vec::new(),
            channels: BTreeMap::new(),
            unchanged_objects: 2,
            unchanged_parameters: None,
            writes: bussard_download::PlanWrites::default(),
            backup_dir: String::new(),
            notes: Vec::new(),
            state_hash: "abc".to_string(),
        };
        let report = PlanReport {
            unchanged: Vec::new(),
            additions: Vec::new(),
            removals: Vec::new(),
            resulting_address_count: 2,
            resulting_association_count: 2,
            current_address_count: 2,
            current_association_count: 2,
            load_steps: Vec::new(),
        };
        change.add_to(&mut plan, &report, None);
        assert!(plan.writes.security_object);
        assert!(plan.writes.address_table.is_some());
        assert!(
            plan.state_hash.starts_with("abc-pid61-"),
            "{}",
            plan.state_hash
        );
        assert_eq!(plan.changes.len(), 1);
        Ok(())
    }

    #[test]
    fn test_cached_flags_hex_roundtrips() {
        let flags = vec![0x00, 0x03, 0x00, 0xFF];
        assert_eq!(to_hex(&flags), "000300FF");
        assert_eq!(from_hex(&to_hex(&flags)), Some(flags));
        assert_eq!(from_hex("0"), None);
        assert_eq!(from_hex("0G"), None);
    }

    #[test]
    fn test_unchanged_cached_flags_without_a_cache_reads_the_device() -> TestResult {
        // No facts record: nothing cached, the plan reads PID 61.
        let dir = std::env::temp_dir().join(format!("bussard-pid61-{}", std::process::id()));
        let desired = desired()?;
        let inputs = SecurityInputs::default();
        assert_eq!(
            unchanged_cached_flags(&dir, ia("1.1.5")?, &desired, &inputs, false),
            None
        );
        Ok(())
    }
}
