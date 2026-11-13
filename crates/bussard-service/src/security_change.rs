//! The plan side of a group address that leaves or joins KNX Data Secure
//! (issue #331): what a Secure device's security object must change so its
//! group key table (PID 53) and group-object security flags (PID 61) match
//! the model and the key store again.
//!
//! The evidence is the device itself: `plan` and `apply` read PID 61 over the
//! secured session ([`bussard_download::read_security_flags`]) and compare it
//! with the flags the model asks for ([`bussard_download::SecurityInputs`]).
//! PID 53 is write-only, so the group key side is compared against the
//! lock's record of the device's group key table
//! (`DeviceSecurity::group_keys`, written after every verified secured write
//! and by `adopt`, issue #1094): exactly the addresses whose key state
//! differs are reported, and the device's live entry count cross-checks the
//! record. Without the project's group keys (a raw tool key) or without a
//! record the key side is not compared, and the plan says so. Group object 0
//! has no PID 61 element: it is secured by its keys alone
//! ([`bussard_download::has_go_flag_element`]).
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

use std::collections::BTreeSet;

use bussard_download::has_go_flag_element;
use bussard_download::{
    ChangeMark, ChangeSubject, DesiredTables, DevicePlan, PlanChange, PlanReport, SecurityInputs,
};
use bussard_model::text::{from_hex, hex_upper};
use bussard_model::{GroupAddress, IndividualAddress, Model};

/// One group address whose Data Secure state changes on a device, with the
/// device's group objects linked to it whose flag changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSecurityDelta {
    /// The group address.
    pub ga: GroupAddress,
    /// The group objects linked to it whose security flag changes, ascending.
    pub objects: Vec<u16>,
    /// The group objects linked to it that have no PID 61 element (group
    /// object 0, issue #1094): the key moves, no flag does.
    pub without_flag: Vec<u16>,
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
    /// The group key table changes (issue #1094): a group address joins or
    /// leaves it against the lock's record of what the device holds, or the
    /// device's entry count no longer matches that record.
    pub keys_change: bool,
    /// The device's group key table entry count (PID 53) against the lock's
    /// record, when they differ: the device changed outside bussard.
    pub key_drift: Option<(usize, usize)>,
    /// Why the group key side was not compared (no key store, no record, a
    /// count that did not read); `None` when it was.
    pub keys_not_compared: Option<String>,
    /// The key state compared, for the state hash: the live count and the
    /// record.
    key_state: String,
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
        // PID 61 shows only the objects with an element: group object 0 is
        // secured with its keys and no flag (issue #1094).
        let flagged = inputs.flagged_objects();
        let cleared: BTreeSet<u16> = live_secured.difference(&flagged).copied().collect();
        let set: BTreeSet<u16> = flagged.difference(&live_secured).copied().collect();
        let linked = bussard_download::linked_objects(desired);
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
                    without_flag: Vec::new(),
                });
            }
            if keyed && !gained.is_empty() {
                added.push(GroupSecurityDelta {
                    ga: *ga,
                    objects: gained,
                    without_flag: Vec::new(),
                });
            }
        }
        SecurityObjectChange {
            device,
            removed,
            added,
            cleared: cleared.into_iter().collect(),
            set: set.into_iter().collect(),
            keys_change: false,
            key_drift: None,
            keys_not_compared: None,
            key_state: String::new(),
            live_secured: live_secured.into_iter().collect(),
        }
    }

    /// Adds the group key table's side (issue #1094). PID 53 is write-only,
    /// so the device's keyed group addresses are the lock's `record` of the
    /// last verified write; the project's are the keyed addresses of the
    /// table being written. Exactly the addresses whose key state differs
    /// are reported, with the objects that carry no flag for them (group
    /// object 0). `live` is the device's entry count, the cross-check that
    /// it still holds the record: a count that disagrees means it changed
    /// outside bussard, and the table is rewritten.
    ///
    /// Not compared, and said so, without the project's group keys
    /// (`keys_known` false: a raw tool key, no key store), without a record,
    /// or when the count did not read.
    pub fn with_keys(
        mut self,
        desired: &DesiredTables,
        inputs: &SecurityInputs,
        keys_known: bool,
        record: Option<&[GroupAddress]>,
        live: Option<&Result<u16, String>>,
    ) -> SecurityObjectChange {
        if !keys_known {
            self.keys_not_compared =
                Some("no key store or keyring gives the project's group keys".to_string());
            return self;
        }
        let Some(record) = record else {
            self.keys_not_compared = Some(
                "bussard.lock has no record of the device's group key table; an apply \
                 establishes it"
                    .to_string(),
            );
            return self;
        };
        let have: BTreeSet<GroupAddress> = record.iter().copied().collect();
        let want: BTreeSet<GroupAddress> = inputs.keyed(&desired.addresses).into_iter().collect();
        let joined: BTreeSet<GroupAddress> = want.difference(&have).copied().collect();
        let left: BTreeSet<GroupAddress> = have.difference(&want).copied().collect();
        // A flag change on an address whose key stays is no key change.
        self.added.retain(|d| joined.contains(&d.ga));
        self.removed.retain(|d| left.contains(&d.ga));
        let linked = bussard_download::linked_objects(desired);
        let unflagged = |ga: &GroupAddress| -> Vec<u16> {
            linked
                .get(ga)
                .into_iter()
                .flatten()
                .copied()
                .filter(|&o| !has_go_flag_element(o))
                .collect()
        };
        for (gas, deltas) in [(&joined, &mut self.added), (&left, &mut self.removed)] {
            for ga in gas {
                let without_flag = unflagged(ga);
                match deltas.iter_mut().find(|d| d.ga == *ga) {
                    Some(delta) => delta.without_flag = without_flag,
                    None => deltas.push(GroupSecurityDelta {
                        ga: *ga,
                        objects: Vec::new(),
                        without_flag,
                    }),
                }
            }
            deltas.sort_by_key(|d| d.ga);
        }
        let list: Vec<String> = have.iter().map(ToString::to_string).collect();
        self.key_state = format!("record {}", list.join(","));
        match live {
            Some(Ok(count)) => {
                self.key_state.push_str(&format!(" live {count}"));
                if usize::from(*count) != have.len() {
                    self.key_drift = Some((usize::from(*count), have.len()));
                }
            }
            Some(Err(why)) => {
                self.keys_not_compared = Some(format!(
                    "the group key table's entry count (PID 53) did not read ({why}); the \
                     record was compared without the cross-check"
                ));
            }
            None => {}
        }
        self.keys_change = !joined.is_empty() || !left.is_empty() || self.key_drift.is_some();
        self
    }

    /// The key state this change compared (record and live count), for the
    /// plan's fingerprint and state hash; empty when not compared.
    pub fn key_state(&self) -> &str {
        &self.key_state
    }

    /// Whether the security object must be written for this change.
    pub fn changes(&self) -> bool {
        !self.cleared.is_empty() || !self.set.is_empty() || self.keys_change
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
        for (deltas, on) in [(&self.removed, false), (&self.added, true)] {
            for delta in deltas {
                attributed.extend(delta.objects.iter().copied());
                parts.push(delta_sentence(&label(delta.ga), delta, on));
            }
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
                 in your project)",
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
        if let Some((live, recorded)) = self.key_drift {
            parts.push(format!(
                "the group key table holds {live} key(s) where the last write recorded \
                 {recorded}: it changed outside bussard, and the write rewrites it (PID 53)"
            ));
        }
        let gains = !self.set.is_empty() || !self.added.is_empty();
        let loses = !self.cleared.is_empty() || !self.removed.is_empty();
        let mark = match (loses, gains) {
            (true, false) => ChangeMark::Removed,
            (false, true) => ChangeMark::Added,
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

    /// Notes on `plan` what the comparison could not check: the group key
    /// side not compared, and why (issue #1094).
    pub fn add_notes(&self, plan: &mut DevicePlan) {
        if let Some(why) = &self.keys_not_compared {
            plan.notes
                .push(format!("group keys (PID 53) not compared: {why}"));
        }
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
        let mut live: Vec<String> = self.live_secured.iter().map(u16::to_string).collect();
        if !self.key_state.is_empty() {
            live.push(self.key_state.clone());
        }
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

/// The plan sentence of one group address joining (`on`) or leaving Data
/// Secure: its key, the objects whose PID 61 flag changes, and the objects
/// that carry no flag for it (group object 0, issue #1094).
fn delta_sentence(label: &str, delta: &GroupSecurityDelta, on: bool) -> String {
    let (word, key) = if on {
        ("on", "joins")
    } else {
        ("off", "leaves")
    };
    let mut out =
        format!("Data Secure {word} for {label}: its group key {key} the group key table (PID 53)");
    if !delta.objects.is_empty() {
        let one = delta.objects.len() == 1;
        let verb = match (on, one) {
            (true, true) => "gets the",
            (true, false) => "get the",
            (false, true) => "loses its",
            (false, false) => "lose its",
        };
        let change = if on { "0x00 to 0x03" } else { "0x03 to 0x00" };
        out.push_str(&format!(
            " and {} {verb} security flag (PID 61 {change})",
            objects_phrase(&delta.objects)
        ));
    }
    if !delta.without_flag.is_empty() {
        out.push_str(&format!(
            "; {} {} no security flag (no PID 61 element)",
            objects_phrase(&delta.without_flag),
            if delta.without_flag.len() == 1 {
                "has"
            } else {
                "have"
            }
        ));
    }
    out
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
    let flags = from_hex(record.go_security_flags.as_deref()?).ok()?;
    (!SecurityObjectChange::compare(target, desired, inputs, &flags).changes()).then_some(flags)
}

/// Caches the PID 61 flags a plan read live from `target` in its device
/// facts (issue #336). Nothing happens without a facts record (no session
/// established facts for the device); a write failure is logged, the cache
/// being optional.
pub fn remember_flags(dir: &std::path::Path, target: IndividualAddress, flags: &[u8]) {
    update_cached_flags(dir, target, Some(hex_upper(flags)));
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

/// What a verified secured write put on a device's security object, for
/// [`record_security_flags`].
#[derive(Debug, Clone, Copy)]
pub struct SecurityRecord<'a> {
    /// The secured objects: the `secure` flag of every linked com-object.
    pub secured: &'a BTreeSet<u16>,
    /// `secured` came from PID 61 flags (a flash's program): an object
    /// without a PID 61 element (group object 0) cannot appear in it and
    /// keeps the model's `secure`. `false` for the model's own secured set
    /// (an apply), which object 0 is part of (issue #1094).
    pub from_flags: bool,
    /// The group addresses the group key table (PID 53) now holds, recorded
    /// as [`bussard_model::schema::DeviceSecurity::group_keys`].
    pub group_keys: &'a BTreeSet<GroupAddress>,
}

/// Records what a verified secured write put on `device`'s security object
/// in the lock: the group-object security flags as the `secure` flag of its
/// linked com-objects (issue #331), and the group addresses its group key
/// table holds (issue #1094), the way `admission::record_secure_senders`
/// records PID 54. A linked object the write left plain is recorded plain, a
/// secured one secured; an object the model does not link keeps its flag.
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
    record: SecurityRecord<'_>,
) -> Result<bool, crate::ServiceError> {
    let secured = record.secured;
    let mut model = Model::load(dir).map_err(|e| {
        crate::ServiceError::because("loading the project to record the security flags", e)
    })?;
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
        // A set read from PID 61 cannot hold an object without an element
        // (group object 0): it keeps the model's `secure` (issue #1094).
        if !linked.contains(number) || (record.from_flags && !has_go_flag_element(*number)) {
            continue;
        }
        let flag = secured.contains(number);
        if co.secure != flag {
            co.secure = flag;
            changed = true;
        }
    }
    let keys: Vec<GroupAddress> = record.group_keys.iter().copied().collect();
    let security = loaded.device.security.get_or_insert_with(Default::default);
    if security.group_keys.as_ref() != Some(&keys) {
        security.group_keys = Some(keys);
        changed = true;
    }
    if changed {
        model.save(dir).map_err(|e| {
            crate::ServiceError::because("saving the security flags to bussard.lock", e)
        })?;
    }
    Ok(changed)
}

/// Records the group addresses a verified secured write put into `device`'s
/// group key table (PID 53, issue #1094) in the lock, without touching the
/// com-object flags: the line apply's record, whose security inputs come
/// from the keyring alone. Returns whether the lock changed.
///
/// # Errors
///
/// The model does not load or save.
pub fn record_group_keys(
    dir: &std::path::Path,
    device: IndividualAddress,
    group_keys: &BTreeSet<GroupAddress>,
) -> Result<bool, crate::ServiceError> {
    let mut model = Model::load(dir).map_err(|e| {
        crate::ServiceError::because("loading the project to record the group keys", e)
    })?;
    let Some(loaded) = model.devices.get_mut(&device) else {
        return Ok(false);
    };
    let keys: Vec<GroupAddress> = group_keys.iter().copied().collect();
    let security = loaded.device.security.get_or_insert_with(Default::default);
    if security.group_keys.as_ref() == Some(&keys) {
        return Ok(false);
    }
    security.group_keys = Some(keys);
    model
        .save(dir)
        .map_err(|e| crate::ServiceError::because("saving the group keys to bussard.lock", e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

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
                objects: vec![12],
                without_flag: Vec::new(),
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

    /// Review of #1094, finding 3, in the capture's shape: object 0 already
    /// keyed on 1/0/1 and 1/0/2 (the lock's record), a secured 1/0/3 added
    /// on object 1. Only 1/0/3 joins the key table; 1/0/1 and 1/0/2 are not
    /// reported.
    #[test]
    fn test_with_keys_reports_only_the_addresses_whose_key_changes() -> TestResult {
        let desired = DesiredTables {
            addresses: vec![ga("1/0/1")?, ga("1/0/2")?, ga("1/0/3")?],
            associations: vec![(1, 0), (2, 0), (3, 1)],
        };
        let mut keys = HashMap::new();
        for g in ["1/0/1", "1/0/2", "1/0/3"] {
            keys.insert(ga(g)?, bussard_secure::Key16::new([1; 16]));
        }
        let inputs = bussard_download::security_inputs_for(None, ia("1.1.1")?, &desired, &keys);
        let record = [ga("1/0/1")?, ga("1/0/2")?];
        let change = SecurityObjectChange::compare(ia("1.1.1")?, &desired, &inputs, &[0])
            .with_keys(&desired, &inputs, true, Some(&record), Some(&Ok(2)));
        let added: Vec<GroupAddress> = change.added.iter().map(|d| d.ga).collect();
        assert_eq!(added, vec![ga("1/0/3")?]);
        assert!(change.removed.is_empty());
        assert_eq!(change.set, vec![1]);
        let line = change.change(None).ok_or("a change")?;
        assert!(!line.sentence.contains("1/0/1"), "{}", line.sentence);
        // Without the project's keys the key side is not compared at all.
        let unknown = SecurityObjectChange::compare(ia("1.1.1")?, &desired, &inputs, &[0x03])
            .with_keys(&desired, &inputs, false, Some(&record), Some(&Ok(9)));
        assert!(!unknown.changes());
        assert!(unknown.keys_not_compared.is_some());
        Ok(())
    }

    #[test]
    fn test_cached_flags_hex_roundtrips() {
        let flags = vec![0x00, 0x03, 0x00, 0xFF];
        assert_eq!(hex_upper(&flags), "000300FF");
        assert_eq!(from_hex(&hex_upper(&flags)).ok(), Some(flags));
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
