//! Programming the KNX Data Secure **security interface object** (object type
//! 17) the way ETS does in a secured download (issue #156).
//!
//! A Data Secure device keeps its group keys and the per-group-object security
//! flags in its security object, not in the link tables. ETS rewrites the
//! object in every full download of an activated device, and bussard must do
//! the same: a download that rewrites the tables but not the security object
//! leaves the device with keys indexed against a stale address table, or with
//! no keys at all after the factory reset.
//!
//! # What ETS writes (CONFIRMED from the decrypted capture `secure-1-1-12.pcapng`)
//!
//! After the tables and parameters, before `PID_PROGRAM_VERSION` and the
//! `LoadCompleted` of the application objects:
//!
//! 1. `A_FunctionPropertyExt_Command` PID 5 = `01 00…` (StartLoading of the
//!    security object's load-state machine; it was unloaded with `04 00…` right
//!    after the other objects' `Unload`s).
//! 2. `A_PropertyExtValue_WriteCon` PID 54 (security individual address
//!    table), element 0 = `00 00`: the table is emptied.
//! 3. `A_PropertyExtValue_WriteCon` PID 53 (group key table), from element 1:
//!    18-octet elements `[address table index:16][group key:16]`, one per keyed
//!    group address the device is linked to. The capture's one element starts
//!    `00 03`: GA 0/3/47 is the third entry of that device's address table
//!    (`0005 0006 032f`), so the index is 1-based into the address table, not
//!    the group address.
//! 4. `A_PropertyExtValue_WriteCon` PID 61 (group-object security flags), from
//!    element 1: one octet per group object, element `n` for group object `n`,
//!    as many elements as the group-object table has (1333 on that device), in
//!    211-element chunks. Group object 1289 (linked to the keyed GA) gets `0x03`,
//!    every other one `0x00`.
//! 5. `A_FunctionPropertyExt_Command` PID 5 = `02 00…` (LoadCompleted).
//!
//! With several keys the entries are written in ascending address-table index
//! (the table is sorted by group address, so this is also GA order) and packed
//! into as few telegrams as the APDU allows: INFERRED, the capture holds one key.
//! The flag value `0x03` sets bit 0 and bit 1, read as authentication and
//! confidentiality (ETS secures group objects with both): INFERRED from the one
//! value seen.
//!
//! Key material: [`SecurityProgram`] holds group keys as [`Key16`], whose
//! `Debug` is redacted; nothing here prints a key.

use std::collections::{BTreeSet, HashMap};

use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{LoadControl, LoadState, WriteError};
use bussard_mgmt::property_ext::{self, PropertyExtAddress};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_secure::Key16;

/// The ETS flag octet for a secured group object (see the module docs).
pub const GO_FLAGS_SECURE: u8 = 0x03;

/// One element of the group key table (`PID_GRP_KEY_TABLE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKeyEntry {
    /// The 1-based index of the group address in the device's address table.
    pub address_index: u16,
    /// The group address (for labels and diagnostics; not written).
    pub group_address: GroupAddress,
    /// The group key (redacted `Debug`).
    pub key: Key16,
}

impl GroupKeyEntry {
    /// The 18 octets written for this element.
    pub fn encode(&self) -> [u8; 18] {
        let mut out = [0u8; 18];
        out[..2].copy_from_slice(&self.address_index.to_be_bytes());
        out[2..].copy_from_slice(self.key.bytes());
        out
    }
}

/// What a secured download writes into the security object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityProgram {
    /// The group key table, in ascending address-table index.
    pub group_keys: Vec<GroupKeyEntry>,
    /// The group-object security flags, element 1 first (index 0 of the vector
    /// is group object 1).
    pub go_flags: Vec<u8>,
}

impl SecurityProgram {
    /// The group objects this program marks secured, ascending.
    pub fn secured_objects(&self) -> Vec<u16> {
        self.go_flags
            .iter()
            .enumerate()
            .filter(|(_, f)| **f != 0)
            .map(|(i, _)| (i + 1) as u16)
            .collect()
    }

    /// The group key table as the octets PID 53 receives.
    pub fn group_key_table_bytes(&self) -> Vec<u8> {
        self.group_keys.iter().flat_map(|e| e.encode()).collect()
    }
}

/// Why a security program could not be built. Every message names addresses
/// and group objects, never a key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecurityPlanError {
    /// The project runs a group address of this device with Data Secure, but the
    /// keyring (or no keyring) carries no key for it.
    #[error(
        "{device}: group address {ga} is Data Secure in the model but the keyring has no key for \
         it; pass the project's current keyring with --keyring (a --tool-key alone carries no \
         group keys)"
    )]
    MissingGroupKey {
        /// The device.
        device: IndividualAddress,
        /// The group address.
        ga: GroupAddress,
    },
    /// A secured group object number lies outside the device's group-object
    /// table.
    #[error(
        "{device}: group object {object} is Data Secure but the group-object table has only \
         {count} object(s)"
    )]
    ObjectOutOfRange {
        /// The device.
        device: IndividualAddress,
        /// The group object number.
        object: u16,
        /// The group-object table's size.
        count: u16,
    },
}

/// Builds the security program for `device` from its final address table
/// (`addresses`, table order: element 1 first), its group-object count, the
/// group objects to secure, the group addresses the project marks secure and
/// the keyring's group keys.
///
/// A group address gets a key-table entry when the keyring has a key for it.
/// A group address the model marks secure without a key is refused. A group
/// object is flagged when it is in `secure_objects`.
pub fn build_security_program(
    device: IndividualAddress,
    addresses: &[GroupAddress],
    go_count: u16,
    secure_objects: &BTreeSet<u16>,
    secure_gas: &BTreeSet<GroupAddress>,
    group_keys: &HashMap<GroupAddress, Key16>,
) -> Result<SecurityProgram, SecurityPlanError> {
    let mut entries = Vec::new();
    for (i, ga) in addresses.iter().enumerate() {
        match group_keys.get(ga) {
            Some(key) => entries.push(GroupKeyEntry {
                address_index: (i + 1) as u16,
                group_address: *ga,
                key: key.clone(),
            }),
            None if secure_gas.contains(ga) => {
                return Err(SecurityPlanError::MissingGroupKey { device, ga: *ga });
            }
            None => {}
        }
    }
    let mut flags = vec![0u8; usize::from(go_count)];
    for &object in secure_objects {
        let slot = usize::from(object)
            .checked_sub(1)
            .and_then(|i| flags.get_mut(i))
            .ok_or(SecurityPlanError::ObjectOutOfRange {
                device,
                object,
                count: go_count,
            })?;
        *slot = GO_FLAGS_SECURE;
    }
    Ok(SecurityProgram {
        group_keys: entries,
        go_flags: flags,
    })
}

/// The Data Secure view of one device in the model: which of its group objects
/// and group addresses run secured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceSecurityView {
    /// Group objects to flag: the model marks them `secure`, or they are linked
    /// to a group address that is secure in the model or keyed in the keyring.
    pub secure_objects: BTreeSet<u16>,
    /// The device's linked group addresses the model marks `secure`.
    pub secure_gas: BTreeSet<GroupAddress>,
}

/// Derives [`DeviceSecurityView`] for `device` from the model and the keyring's
/// group keys.
///
/// The keyring is the practical source when the project export carries no
/// explicit per-object setting (the case in the reference export, issue #156):
/// a group object linked to a group address the keyring holds a key for is
/// secured. The model's own flags (imported from the project) are honoured on
/// top, so a stale keyring cannot silently drop a secured object.
pub fn device_security_view(
    model: Option<&Model>,
    device: IndividualAddress,
    group_keys: &HashMap<GroupAddress, Key16>,
) -> DeviceSecurityView {
    let mut view = DeviceSecurityView::default();
    let Some(model) = model else {
        return view;
    };
    let links = model
        .links
        .links
        .get(&device)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for link in links {
        for ga in link.send.iter().chain(link.listen.iter()) {
            let ga_secure = model.groups.groups.get(ga).is_some_and(|g| g.secure);
            if ga_secure {
                view.secure_gas.insert(*ga);
            }
            if ga_secure || group_keys.contains_key(ga) {
                view.secure_objects.insert(link.object);
            }
        }
    }
    if let Some(loaded) = model.devices.get(&device) {
        let linked: BTreeSet<u16> = links.iter().map(|l| l.object).collect();
        for (number, co) in &loaded.device.com_objects {
            // Only a linked object communicates at all; an unlinked object's
            // flag is irrelevant and ETS's capture flags only linked ones.
            if co.secure && linked.contains(number) {
                view.secure_objects.insert(*number);
            }
        }
    }
    view
}

/// What `apply --keyring` needs to reprogram the security object next to the
/// link tables (issue #156): the model's and keyring's view of the device.
#[derive(Debug, Clone, Default)]
pub struct SecurityInputs {
    /// Group objects to flag secured.
    pub secure_objects: BTreeSet<u16>,
    /// Linked group addresses the model marks secure (each must have a key).
    pub secure_gas: BTreeSet<GroupAddress>,
    /// The keyring's group keys.
    pub group_keys: HashMap<GroupAddress, Key16>,
    /// The group-object count to use when the device does not report the
    /// element count of `PID_GO_SECURITY_FLAGS` (the highest object number the
    /// model knows).
    pub fallback_go_count: u16,
}

/// Derives the [`SecurityInputs`] for writing `desired` (an address and
/// association table, from the model or a backup) to `device`: a group object
/// is secured when an association links it to a group address that is keyed in
/// the keyring or secure in the model, or when the model marks the object
/// `secure` and the tables link it at all.
pub fn security_inputs_for(
    model: Option<&Model>,
    device: IndividualAddress,
    desired: &crate::compute::DesiredTables,
    group_keys: &HashMap<GroupAddress, Key16>,
) -> SecurityInputs {
    let ga_secure = |ga: &GroupAddress| {
        model
            .and_then(|m| m.groups.groups.get(ga))
            .is_some_and(|g| g.secure)
    };
    let loaded = model.and_then(|m| m.devices.get(&device));
    let mut inputs = SecurityInputs {
        group_keys: group_keys.clone(),
        fallback_go_count: loaded
            .and_then(|d| d.device.com_objects.keys().max().copied())
            .unwrap_or(0),
        ..SecurityInputs::default()
    };
    for &(tsap, asap) in &desired.associations {
        let Some(ga) = usize::from(tsap)
            .checked_sub(1)
            .and_then(|i| desired.addresses.get(i))
        else {
            continue;
        };
        let secure = ga_secure(ga);
        if secure {
            inputs.secure_gas.insert(*ga);
        }
        let co_secure = loaded
            .and_then(|d| d.device.com_objects.get(&asap))
            .is_some_and(|co| co.secure);
        if secure || co_secure || group_keys.contains_key(ga) {
            inputs.secure_objects.insert(asap);
        }
    }
    inputs.fallback_go_count = inputs
        .fallback_go_count
        .max(inputs.secure_objects.iter().max().copied().unwrap_or(0));
    inputs
}

/// Sends a load-control event to the security object and checks the state it
/// reports (`Unload` → `Unloaded`, `StartLoading` → `Loading`,
/// `LoadCompleted` → `Loaded`).
pub async fn security_transition<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    control: LoadControl,
) -> Result<(), WriteError> {
    let expected = match control {
        LoadControl::Unload => LoadState::Unloaded,
        LoadControl::StartLoading => LoadState::Loading,
        _ => LoadState::Loaded,
    };
    let actual = property_ext::security_load_control(l4, control).await?;
    if actual != expected {
        return Err(WriteError::SecurityObjectState {
            address: l4.target(),
            control,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Empties the security individual address table (PID 54, element 0 = 0).
pub async fn clear_security_address_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<(), WriteError> {
    property_ext::write_property_ext_con(
        l4,
        PropertyExtAddress::security(property_ext::PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE),
        1,
        0,
        &[0x00, 0x00],
    )
    .await?;
    Ok(())
}

/// Writes the group key table (PID 53) from element 1.
pub async fn write_group_key_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    entries: &[GroupKeyEntry],
) -> Result<(), WriteError> {
    if entries.is_empty() {
        return Ok(());
    }
    let table: Vec<u8> = entries.iter().flat_map(|e| e.encode()).collect();
    property_ext::write_property_ext_chunked(
        l4,
        PropertyExtAddress::security(property_ext::PID_GRP_KEY_TABLE),
        1,
        18,
        &table,
        |_| {},
    )
    .await?;
    Ok(())
}

/// Writes the group-object security flags (PID 61) from element 1;
/// `on_chunk` receives the number of elements written so far.
pub async fn write_go_security_flags<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    flags: &[u8],
    on_chunk: impl FnMut(usize),
) -> Result<(), WriteError> {
    if flags.is_empty() {
        return Ok(());
    }
    property_ext::write_property_ext_chunked(
        l4,
        PropertyExtAddress::security(property_ext::PID_GO_SECURITY_FLAGS),
        1,
        1,
        flags,
        on_chunk,
    )
    .await?;
    Ok(())
}

/// Reprograms the whole security object for the address table `addresses`, as
/// `apply --keyring` does next to the link tables: `Unload`, `StartLoading`,
/// the IA-table clear, the group key table, the group-object flags,
/// `LoadCompleted` (the ETS order, see the module docs).
///
/// The group-object count is read from the device (`PID_GO_SECURITY_FLAGS`
/// element count); a device that refuses the read falls back to
/// [`SecurityInputs::fallback_go_count`].
pub async fn program_security_object<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addresses: &[GroupAddress],
    inputs: &SecurityInputs,
) -> Result<SecurityProgram, WriteError> {
    let go_count = match property_ext::read_property_ext_element_count(
        l4,
        PropertyExtAddress::security(property_ext::PID_GO_SECURITY_FLAGS),
    )
    .await
    {
        Ok(n) => n,
        Err(MgmtError::ServiceRejected { .. }) | Err(MgmtError::MalformedResponse { .. }) => {
            inputs.fallback_go_count
        }
        Err(other) => return Err(WriteError::Mgmt(other)),
    };
    let program = build_security_program(
        l4.target(),
        addresses,
        go_count,
        &inputs.secure_objects,
        &inputs.secure_gas,
        &inputs.group_keys,
    )
    .map_err(|e| WriteError::SecurityProgram {
        address: l4.target(),
        reason: e.to_string(),
    })?;
    security_transition(l4, LoadControl::Unload).await?;
    security_transition(l4, LoadControl::StartLoading).await?;
    clear_security_address_table(l4).await?;
    write_group_key_table(l4, &program.group_keys).await?;
    write_go_security_flags(l4, &program.go_flags, |_| {}).await?;
    security_transition(l4, LoadControl::LoadCompleted).await?;
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ga(s: &str) -> Result<GroupAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    #[test]
    fn test_build_security_program_matches_capture_structure() -> TestResult {
        // 1.1.12 in the capture: address table 0/0/5, 0/0/6, 0/3/47; GO table of
        // 1333 objects; GO 1289 linked to the keyed 0/3/47.
        let device: IndividualAddress = "1.1.12".parse()?;
        let addresses = vec![ga("0/0/5")?, ga("0/0/6")?, ga("0/3/47")?];
        let mut keys = HashMap::new();
        keys.insert(ga("0/3/47")?, Key16::new([0x5A; 16]));
        let program = build_security_program(
            device,
            &addresses,
            1333,
            &BTreeSet::from([1289]),
            &BTreeSet::new(),
            &keys,
        )?;
        assert_eq!(program.group_keys.len(), 1);
        let table = program.group_key_table_bytes();
        assert_eq!(table.len(), 18);
        assert_eq!(&table[..2], &[0x00, 0x03]);
        assert_eq!(program.go_flags.len(), 1333);
        assert_eq!(program.secured_objects(), vec![1289]);
        // The last ETS chunk (index 1267, 67 elements) carries 0x03 at offset 22.
        assert_eq!(program.go_flags[1266 + 22], GO_FLAGS_SECURE);
        Ok(())
    }

    #[test]
    fn test_build_security_program_refuses_a_secure_ga_without_key() -> TestResult {
        let device: IndividualAddress = "1.1.12".parse()?;
        let addresses = vec![ga("0/3/47")?];
        let err = build_security_program(
            device,
            &addresses,
            10,
            &BTreeSet::new(),
            &BTreeSet::from([ga("0/3/47")?]),
            &HashMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        assert!(matches!(err, SecurityPlanError::MissingGroupKey { .. }));
        assert!(err.to_string().contains("0/3/47"));
        Ok(())
    }

    #[test]
    fn test_build_security_program_refuses_an_object_beyond_the_table() -> TestResult {
        let device: IndividualAddress = "1.1.12".parse()?;
        let err = build_security_program(
            device,
            &[],
            4,
            &BTreeSet::from([5]),
            &BTreeSet::new(),
            &HashMap::new(),
        )
        .err()
        .ok_or("expected an error")?;
        assert!(matches!(err, SecurityPlanError::ObjectOutOfRange { .. }));
        Ok(())
    }

    #[test]
    fn test_group_key_entries_follow_address_table_order() -> TestResult {
        let device: IndividualAddress = "1.1.1".parse()?;
        let addresses = vec![ga("1/0/1")?, ga("1/0/2")?, ga("1/0/3")?];
        let mut keys = HashMap::new();
        keys.insert(ga("1/0/3")?, Key16::new([3; 16]));
        keys.insert(ga("1/0/1")?, Key16::new([1; 16]));
        keys.insert(ga("9/0/0")?, Key16::new([9; 16])); // not linked: ignored
        let program = build_security_program(
            device,
            &addresses,
            0,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &keys,
        )?;
        let idx: Vec<u16> = program.group_keys.iter().map(|e| e.address_index).collect();
        assert_eq!(idx, vec![1, 3]);
        Ok(())
    }

    #[test]
    fn test_security_program_debug_never_prints_keys() -> TestResult {
        let entry = GroupKeyEntry {
            address_index: 1,
            group_address: ga("1/0/1")?,
            key: Key16::new([0xAB; 16]),
        };
        let s = format!("{entry:?}");
        assert!(
            !s.contains("171") && !s.to_lowercase().contains("ab, ab"),
            "{s}"
        );
        Ok(())
    }
}
