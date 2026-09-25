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
//!    table), element 0 = `00 00`: the table is emptied. Then, on a device
//!    that receives secured group telegrams from other devices, the entries
//!    from element 1: 8-octet elements `[sender IA:2][sender sequence:6]`, one
//!    per secured sender (CONFIRMED from the S3 captures of 2026-09-24,
//!    issue #181; see [`secured_senders`] for the rule).
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
//! into as few telegrams as the APDU allows. CONFIRMED by the S3 captures of
//! 2026-09-24 (address-table indices only, keys never printed): 1.1.5 got 16
//! entries as 11 from element 1 (indices 1, 2, 6, 8, 9, 10, 12, 14, 17, 18,
//! 19; 198 octets, the most that fits the 211-octet budget) and 5 from element
//! 12 (20, 23, 24, 25, 26); 1.1.7 got 8 in one telegram, 1.1.9 3, 1.1.16 4,
//! 1.1.47 and 1.1.48 2, always ascending.
//! The flag octets: only `0x00` ([`GO_FLAGS_PLAIN`]) and `0x03`
//! ([`GO_FLAGS_SECURE`]) occur in those captures, and bussard writes only
//! those. Reading `0x03` as bit 0 authentication and bit 1 confidentiality is
//! INFERRED; [`read_security_object`] reports any other value it reads back.
//!
//! Key material: [`SecurityProgram`] holds group keys as [`Key16`], whose
//! `Debug` is redacted; nothing here prints a key.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{LoadControl, LoadState, WriteError};
use bussard_mgmt::property_ext::{self, PropertyExtAddress};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_secure::Key16;

/// The ETS flag octet for a group object that is not secured.
///
/// CONFIRMED: every PID 61 element of the eight decrypted ETS downloads
/// (`secure-1-1-{5,7,9,12,16,47,48}.pcapng`, `secure-1-1-12-group.pcapng`;
/// 9013 group-object elements in all) is `0x00` or [`GO_FLAGS_SECURE`].
pub const GO_FLAGS_PLAIN: u8 = 0x00;

/// The ETS flag octet for a secured group object.
///
/// CONFIRMED as a value: the 42 secured objects of the eight ETS downloads
/// (1.1.5: 16, 1.1.7: 8, 1.1.9: 6, 1.1.12: 1 and 3, 1.1.16: 4, 1.1.47: 2,
/// 1.1.48: 2) are all `0x03`, and no other non-zero value occurs. INFERRED:
/// the meaning of the bits (bit 0 authentication, bit 1 confidentiality), and
/// so what `0x01` or `0x02` would do. bussard writes only these two values.
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

/// The largest value of a 6-octet Data Secure sequence number.
pub const MAX_SEQUENCE: u64 = (1 << 48) - 1;

/// One element of the security individual address table
/// (`PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE`, PID 54): a device that sends
/// secured group telegrams this device receives, and the last sequence number
/// the project knows for it. Not key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureSenderEntry {
    /// The sender's individual address.
    pub address: IndividualAddress,
    /// The sender's sequence number (48 bits; larger values are clamped).
    pub sequence: u64,
}

impl SecureSenderEntry {
    /// The octets per element.
    pub const LEN: usize = 8;

    /// The 8 octets written for this element: `[IA:2][sequence:6]`, big-endian
    /// (CONFIRMED: 1.1.16 received `1105 0040102ea9ce` for sender 1.1.5 with
    /// the keyring sequence 275149400526).
    pub fn encode(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..2].copy_from_slice(&self.address.raw().to_be_bytes());
        out[2..].copy_from_slice(&self.sequence.min(MAX_SEQUENCE).to_be_bytes()[2..]);
        out
    }

    /// Parses one 8-octet element as [`encode`](Self::encode) writes it, or
    /// `None` for a short slice.
    pub fn decode(element: &[u8]) -> Option<SecureSenderEntry> {
        let e = element.get(..Self::LEN)?;
        let mut seq = [0u8; 8];
        seq[2..].copy_from_slice(&e[2..]);
        Some(SecureSenderEntry {
            address: IndividualAddress::from_raw(u16::from_be_bytes([e[0], e[1]])),
            sequence: u64::from_be_bytes(seq),
        })
    }
}

/// Parses the octets PID 54 answers from element 1 into entries, the inverse
/// of [`sender_table_bytes`]. A trailing partial element is ignored, and so is
/// an all-zero element (individual address 0.0.0 never sends).
pub fn decode_sender_table(bytes: &[u8]) -> Vec<SecureSenderEntry> {
    bytes
        .as_chunks::<{ SecureSenderEntry::LEN }>()
        .0
        .iter()
        .filter_map(|element| SecureSenderEntry::decode(element))
        .filter(|e| e.address.raw() != 0)
        .collect()
}

/// The security individual address table as the octets PID 54 receives from
/// element 1.
pub fn sender_table_bytes(entries: &[SecureSenderEntry]) -> Vec<u8> {
    entries.iter().flat_map(|e| e.encode()).collect()
}

/// Derives the security individual address table (PID 54) of `device` from the
/// model, the way ETS fills it (issue #181):
///
/// - the device's **secured listened group addresses**: every GA in a `listen`
///   link of the device that the model marks `secure` or the keyring holds a
///   group key for;
/// - the **senders**: every other device with a `send` link on one of those
///   addresses (the device itself is never listed);
/// - each sender's sequence is its keyring `SequenceNumber` (`sequences`) when
///   the model marks the sender `activated` (ETS has loaded its tool key), and
///   0 otherwise or when the keyring has none. CONFIRMED: ETS wrote the keyring
///   value of the activated 1.1.5, and 0 for 1.1.10, which is only configured
///   for Secure (`secure_commissioning`, not `activated`) and whose keyring
///   value is a stale project value;
/// - the device's recorded table (`security.secure_senders` in the lock, what
///   `bussard adopt` read back from PID 54) adds every sender the links do not
///   imply, with its recorded sequence;
/// - `extra` adds more senders with sequence 0 (bussard's own tunnel address
///   via `--secure-sender`), unless already listed or equal to `device`.
///
/// The entries are in ascending individual address, packed like the other
/// tables of the security object. Evidence (issue #197): all eight decrypted
/// ETS downloads (`secure-1-1-{5,7,9,12,16,47,48}.pcapng`,
/// `secure-1-1-12-group.pcapng`) write PID 54 as the count-0 clear at element
/// 0 and then at most ONE entry at element 1 (1.1.5: `1110 000000000000`,
/// 1.1.7: `110a 000000000000`, 1.1.16 and 1.1.12: `1105 0040102ea9ce`), so
/// no capture shows the order of several entries; the reference installation
/// has no GA with two secured senders. ETS writes the group key table (PID 53)
/// of the same object in ascending element order, packed to the APDU budget
/// (CONFIRMED, module docs), and the multi-entry PID 54 follows that shape:
/// ascending IA, 26 entries per telegram at `PID_MAX_APDU_LENGTH` 233. The
/// order of several entries stays INFERRED until a device with two secured
/// senders is captured.
pub fn secured_senders(
    model: Option<&Model>,
    device: IndividualAddress,
    group_keys: &HashMap<GroupAddress, Key16>,
    sequences: &HashMap<IndividualAddress, u64>,
    extra: &[IndividualAddress],
) -> Vec<SecureSenderEntry> {
    let mut senders: BTreeMap<IndividualAddress, u64> = BTreeMap::new();
    if let Some(model) = model {
        let secure_listened: BTreeSet<GroupAddress> = model
            .links
            .links
            .get(&device)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .flat_map(|link| link.listen.iter().copied())
            .filter(|ga| {
                group_keys.contains_key(ga) || model.groups.groups.get(ga).is_some_and(|g| g.secure)
            })
            .collect();
        for (peer, links) in &model.links.links {
            if *peer == device {
                continue;
            }
            let sends_secured = links
                .iter()
                .filter_map(|link| link.send)
                .any(|ga| secure_listened.contains(&ga));
            if sends_secured {
                let activated = model
                    .devices
                    .get(peer)
                    .and_then(|d| d.device.security.as_ref())
                    .is_some_and(|s| s.activated);
                let sequence = if activated {
                    sequences.get(peer).copied().unwrap_or(0)
                } else {
                    0
                };
                senders.insert(*peer, sequence);
            }
        }
    }
    // The table the device held when it was adopted (issue #201): a sender
    // the links above do not imply keeps its recorded sequence, so a download
    // does not drop a sender the model does not describe.
    if let Some(recorded) = model
        .and_then(|m| m.devices.get(&device))
        .and_then(|d| d.device.security.as_ref())
    {
        for sender in &recorded.secure_senders {
            if sender.address != device {
                senders.entry(sender.address).or_insert(sender.sequence);
            }
        }
    }
    for ia in extra {
        if *ia != device {
            senders.entry(*ia).or_insert(0);
        }
    }
    senders
        .into_iter()
        .map(|(address, sequence)| SecureSenderEntry { address, sequence })
        .collect()
}

/// What a secured download writes into the security object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityProgram {
    /// The security individual address table (PID 54) from element 1, in
    /// ascending individual address; empty for a device no secured sender
    /// addresses.
    pub senders: Vec<SecureSenderEntry>,
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
        senders: Vec::new(),
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
    /// The security individual address table (PID 54) entries, from
    /// [`secured_senders`]; empty writes only the clear.
    pub senders: Vec<SecureSenderEntry>,
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

impl SecurityInputs {
    /// The keyed group addresses of `addresses` (the address table being
    /// written), in table order: the ones the group key table will index.
    pub fn keyed(&self, addresses: &[GroupAddress]) -> Vec<GroupAddress> {
        addresses
            .iter()
            .filter(|ga| self.group_keys.contains_key(ga))
            .copied()
            .collect()
    }

    /// One line saying what the security object receives next to the
    /// address table `addresses`: the secured senders with their sequence
    /// numbers, the keyed group addresses and the secured group objects. It
    /// names addresses and object numbers only, never a key; `bussard apply
    /// --keyring` prints it and `knx_plan_device` returns it (issue #205).
    pub fn describe(&self, addresses: &[GroupAddress]) -> String {
        let keyed: Vec<String> = self
            .keyed(addresses)
            .iter()
            .map(ToString::to_string)
            .collect();
        let objects: Vec<String> = self
            .secure_objects
            .iter()
            .map(ToString::to_string)
            .collect();
        let senders: Vec<String> = self
            .senders
            .iter()
            .map(|e| format!("{} seq {}", e.address, e.sequence))
            .collect();
        format!(
            "Data Secure: the security object is reprogrammed too (unload, security individual \
             address table: {}, group key table: {}, group-object flags: {}, complete)",
            if senders.is_empty() {
                "no secured senders".to_string()
            } else {
                format!("{} secured sender(s) {}", senders.len(), senders.join(", "))
            },
            if keyed.is_empty() {
                "no keys".to_string()
            } else {
                keyed.join(", ")
            },
            if objects.is_empty() {
                "none secured".to_string()
            } else {
                format!("secured {}", objects.join(", "))
            },
        )
    }
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

/// Writes the security individual address table entries (PID 54) from
/// element 1, chunked to the APDU budget like the group key table. Nothing is
/// sent for an empty table (the clear already emptied it).
pub async fn write_security_address_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    entries: &[SecureSenderEntry],
) -> Result<(), WriteError> {
    if entries.is_empty() {
        return Ok(());
    }
    property_ext::write_property_ext_chunked(
        l4,
        PropertyExtAddress::security(property_ext::PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE),
        1,
        SecureSenderEntry::LEN,
        &sender_table_bytes(entries),
        |_| {},
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

/// What the security object of an activated device holds, read back over the
/// secured session (issue #201). Not key material: the key tables (PID 53,
/// PID 56) are write-only and never read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityReadback {
    /// The group-object security flags (PID 61), element 1 first (index 0 is
    /// group object 1); `None` when the device refused the read.
    pub go_flags: Option<Vec<u8>>,
    /// The security individual address table (PID 54); `None` when the device
    /// refused the read.
    pub senders: Option<Vec<SecureSenderEntry>>,
    /// Why a property is missing, one line each (no value octets).
    pub notes: Vec<String>,
}

impl SecurityReadback {
    /// The group objects whose PID 61 octet is neither [`GO_FLAGS_PLAIN`] nor
    /// [`GO_FLAGS_SECURE`], with the octet, ascending. No ETS download has
    /// written such a value; [`secured_objects`](Self::secured_objects)
    /// counts them as secured, and a secured download rewrites them as `0x03`.
    pub fn unconfirmed_flags(&self) -> Vec<(u16, u8)> {
        self.go_flags
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .enumerate()
            .filter(|(_, f)| **f != GO_FLAGS_PLAIN && **f != GO_FLAGS_SECURE)
            .filter_map(|(i, f)| u16::try_from(i + 1).ok().map(|object| (object, *f)))
            .collect()
    }

    /// The group objects the device flags secured (a non-zero PID 61 octet),
    /// ascending; `None` when PID 61 was not read.
    pub fn secured_objects(&self) -> Option<BTreeSet<u16>> {
        self.go_flags.as_ref().map(|flags| {
            flags
                .iter()
                .enumerate()
                .filter(|(_, f)| **f != 0)
                .filter_map(|(i, _)| u16::try_from(i + 1).ok())
                .collect()
        })
    }
}

/// Reads the group-object security flags (PID 61) and the security individual
/// address table (PID 54) of the security object, the read-side twin of
/// [`program_security_object`]. Read-only: only `A_PropertyExtValue_Read` is
/// sent, in chunks sized to the negotiated APDU budget (the element counts
/// first, as the writer does).
///
/// Best effort per property: a device that refuses one (count 0, a malformed
/// answer) leaves that field `None` with a note, and the other is still read.
/// A transport failure (disconnect, timeout) ends the read with the error.
///
/// # Errors
///
/// A transport-level management error.
pub async fn read_security_object<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<SecurityReadback, MgmtError> {
    let mut readback = SecurityReadback::default();
    let flags = property_ext::read_property_ext_table(
        l4,
        PropertyExtAddress::security(property_ext::PID_GO_SECURITY_FLAGS),
        1,
    )
    .await;
    match flags {
        Ok(bytes) => {
            readback.go_flags = Some(bytes);
            if let Some(note) = unconfirmed_flags_note(&readback.unconfirmed_flags()) {
                readback.notes.push(note);
            }
        }
        Err(err @ (MgmtError::ServiceRejected { .. } | MgmtError::MalformedResponse { .. })) => {
            readback
                .notes
                .push(format!("GO security flags (PID 61) not read: {err}"));
        }
        Err(err) => return Err(err),
    }
    let table = property_ext::read_property_ext_table(
        l4,
        PropertyExtAddress::security(property_ext::PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE),
        SecureSenderEntry::LEN,
    )
    .await;
    match table {
        Ok(bytes) => readback.senders = Some(decode_sender_table(&bytes)),
        Err(err @ (MgmtError::ServiceRejected { .. } | MgmtError::MalformedResponse { .. })) => {
            readback.notes.push(format!(
                "security individual address table (PID 54) not read: {err}"
            ));
        }
        Err(err) => return Err(err),
    }
    Ok(readback)
}

/// The note for group objects whose PID 61 octet is not one ETS writes, or
/// `None` when there are none. Lists the first eight.
fn unconfirmed_flags_note(unconfirmed: &[(u16, u8)]) -> Option<String> {
    if unconfirmed.is_empty() {
        return None;
    }
    let shown: Vec<String> = unconfirmed
        .iter()
        .take(8)
        .map(|(object, flag)| format!("{object}: 0x{flag:02x}"))
        .collect();
    let more = unconfirmed.len() - shown.len();
    let more = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    Some(format!(
        "GO security flags (PID 61): {} group object(s) carry a value ETS has not been seen to \
         write (only 0x00 and 0x03 are confirmed): {}{more}. They count as secured; a secured \
         download rewrites them as 0x03",
        unconfirmed.len(),
        shown.join(", ")
    ))
}

/// Reprograms the whole security object for the address table `addresses`, as
/// `apply --keyring` does next to the link tables: `Unload`, `StartLoading`,
/// the IA-table clear and entries, the group key table, the group-object flags,
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
    let program = SecurityProgram {
        senders: inputs.senders.clone(),
        ..program
    };
    security_transition(l4, LoadControl::Unload).await?;
    security_transition(l4, LoadControl::StartLoading).await?;
    clear_security_address_table(l4).await?;
    write_security_address_table(l4, &program.senders).await?;
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
    fn test_group_key_table_packs_like_the_ets_capture_of_1_1_5() -> TestResult {
        // secure-1-1-5.pcapng: 16 keyed GAs at these 1-based address-table
        // indices, written as 11 elements from element 1 and 5 from element
        // 12 (211-octet budget / 18 octets = 11). Synthetic keys.
        let ets_indices: [u16; 16] = [1, 2, 6, 8, 9, 10, 12, 14, 17, 18, 19, 20, 23, 24, 25, 26];
        let addresses: Vec<GroupAddress> = (1..=26u16)
            .map(|i| GroupAddress::from_raw(0x0800 + i))
            .collect();
        let mut keys = HashMap::new();
        // Inserted in reverse to show the order comes from the table.
        for &i in ets_indices.iter().rev() {
            let ga = addresses
                .get(usize::from(i) - 1)
                .copied()
                .ok_or("index in range")?;
            keys.insert(ga, Key16::new([i as u8; 16]));
        }
        let program = build_security_program(
            "1.1.5".parse()?,
            &addresses,
            0,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &keys,
        )?;
        let idx: Vec<u16> = program.group_keys.iter().map(|e| e.address_index).collect();
        assert_eq!(idx, ets_indices.to_vec());
        let per_telegram = 211 / 18;
        let counts: Vec<usize> = program
            .group_key_table_bytes()
            .chunks(per_telegram * 18)
            .map(|c| c.len() / 18)
            .collect();
        assert_eq!(counts, vec![11, 5]);
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

    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    fn link(
        object: u16,
        send: Option<&str>,
        listen: &[&str],
    ) -> Result<bussard_model::schema::Link, Box<dyn std::error::Error>> {
        Ok(bussard_model::schema::Link {
            object,
            name: None,
            send: send.map(str::parse).transpose()?,
            listen: listen.iter().map(|g| g.parse()).collect::<Result<_, _>>()?,
        })
    }

    /// The S3 reference installation, reduced: the actuator 1.1.5 listens to
    /// the switch 0/0/9 sent by the push button 1.1.16 and sends the status
    /// 0/0/10 the push button listens to; 1.1.9 listens only to a plain GA;
    /// 1.1.30 sends on a secure GA nobody else listens to.
    fn s3_model() -> Result<Model, Box<dyn std::error::Error>> {
        let mut groups = bussard_model::schema::Groups::default();
        for (g, secure) in [
            ("0/0/9", true),
            ("0/0/10", true),
            ("0/0/11", false),
            ("0/0/12", true),
        ] {
            groups.groups.insert(
                g.parse()?,
                bussard_model::schema::Group {
                    name: g.to_string(),
                    secure,
                    ..Default::default()
                },
            );
        }
        let mut links = bussard_model::schema::Links::default();
        links
            .links
            .insert(ia("1.1.5")?, vec![link(1, Some("0/0/10"), &["0/0/9"])?]);
        links
            .links
            .insert(ia("1.1.16")?, vec![link(1, Some("0/0/9"), &["0/0/10"])?]);
        links
            .links
            .insert(ia("1.1.9")?, vec![link(1, None, &["0/0/11"])?]);
        links.links.insert(
            ia("1.1.30")?,
            vec![link(1, Some("0/0/11"), &[])?, link(2, Some("0/0/12"), &[])?],
        );
        // 1.1.5 is activated; 1.1.16 is only configured for Secure (a tool
        // key in the project, never downloaded), like 1.1.10 in the S3 export.
        let mut devices = std::collections::BTreeMap::new();
        for (addr, activated) in [("1.1.5", true), ("1.1.16", false)] {
            let device = bussard_model::schema::Device {
                address: ia(addr)?,
                name: addr.to_string(),
                description: None,
                location: None,
                product: None,
                channels: Default::default(),
                parameters: Default::default(),
                module_bases: Default::default(),
                com_objects: Default::default(),
                security: Some(bussard_model::schema::DeviceSecurity {
                    secure_capable: true,
                    activated,
                    secure_commissioning: true,
                    ..Default::default()
                }),
                replaced: None,
                application_override: None,
                lock: Default::default(),
            };
            devices.insert(
                device.address,
                bussard_model::LoadedDevice {
                    device,
                    file_stem: addr.to_string(),
                },
            );
        }
        Ok(Model {
            config: bussard_model::schema::BussardConfig::default(),
            groups,
            links,
            devices,
        })
    }

    #[test]
    fn test_secure_sender_entry_encode_matches_capture() -> TestResult {
        // 1.1.16 in secure-1-1-16.pcapng: sender 1.1.5, keyring sequence
        // 275149400526.
        let entry = SecureSenderEntry {
            address: ia("1.1.5")?,
            sequence: 275_149_400_526,
        };
        assert_eq!(
            entry.encode(),
            [0x11, 0x05, 0x00, 0x40, 0x10, 0x2e, 0xa9, 0xce]
        );
        // 1.1.5 in secure-1-1-5.pcapng: sender 1.1.16, sequence 0.
        let entry = SecureSenderEntry {
            address: ia("1.1.16")?,
            sequence: 0,
        };
        assert_eq!(entry.encode(), [0x11, 0x10, 0, 0, 0, 0, 0, 0]);
        // A value beyond 48 bits is clamped, never truncated to a small one.
        let entry = SecureSenderEntry {
            address: ia("1.1.1")?,
            sequence: u64::MAX,
        };
        assert_eq!(&entry.encode()[2..], &[0xff; 6]);
        Ok(())
    }

    #[test]
    fn test_secured_senders_follows_secure_listen_links() -> TestResult {
        let model = s3_model()?;
        let keys = HashMap::new();
        let mut seqs = HashMap::new();
        seqs.insert(ia("1.1.5")?, 275_149_400_526u64);
        // A stale project value for the not-activated 1.1.16: ignored, as ETS
        // ignored 1.1.10's.
        seqs.insert(ia("1.1.16")?, 239_366_808_908u64);
        let s = secured_senders(Some(&model), ia("1.1.5")?, &keys, &seqs, &[]);
        assert_eq!(
            s,
            vec![SecureSenderEntry {
                address: ia("1.1.16")?,
                sequence: 0
            }]
        );
        let s = secured_senders(Some(&model), ia("1.1.16")?, &keys, &seqs, &[]);
        assert_eq!(
            s,
            vec![SecureSenderEntry {
                address: ia("1.1.5")?,
                sequence: 275_149_400_526
            }]
        );
        // A plain listened GA contributes no sender.
        assert!(secured_senders(Some(&model), ia("1.1.9")?, &keys, &seqs, &[]).is_empty());
        // No model: no derived senders.
        assert!(secured_senders(None, ia("1.1.5")?, &keys, &seqs, &[]).is_empty());
        // A keyring key makes a GA secure even without the model flag.
        keys_make_secure(&model)?;
        Ok(())
    }

    fn keys_make_secure(model: &Model) -> TestResult {
        let mut keys = HashMap::new();
        keys.insert(ga("0/0/11")?, Key16::new([1; 16]));
        let s = secured_senders(Some(model), ia("1.1.9")?, &keys, &HashMap::new(), &[]);
        assert_eq!(
            s,
            vec![SecureSenderEntry {
                address: ia("1.1.30")?,
                sequence: 0
            }]
        );
        Ok(())
    }

    #[test]
    fn test_secured_senders_extra_is_ascending_and_deduplicated() -> TestResult {
        let model = s3_model()?;
        let s = secured_senders(
            Some(&model),
            ia("1.1.5")?,
            &HashMap::new(),
            &HashMap::new(),
            &[ia("1.1.200")?, ia("1.1.16")?, ia("1.0.0")?, ia("1.1.5")?],
        );
        let addrs: Vec<String> = s.iter().map(|e| e.address.to_string()).collect();
        assert_eq!(addrs, vec!["1.0.0", "1.1.16", "1.1.200"]);
        assert!(s.iter().all(|e| e.sequence == 0));
        assert_eq!(sender_table_bytes(&s).len(), 24);
        Ok(())
    }

    #[test]
    fn test_secured_senders_several_from_links_are_ascending() -> TestResult {
        let mut model = s3_model()?;
        // 1.1.9 also listens to the secured 0/0/12 (sent by 1.1.30) and 0/0/9
        // (sent by 1.1.16): two senders, a table no capture holds yet.
        model
            .links
            .links
            .insert(ia("1.1.9")?, vec![link(1, None, &["0/0/12", "0/0/9"])?]);
        let s = secured_senders(
            Some(&model),
            ia("1.1.9")?,
            &HashMap::new(),
            &HashMap::from([(ia("1.1.30")?, 7), (ia("1.1.16")?, 8)]),
            &[],
        );
        // Neither sender is activated in the model, so both get sequence 0.
        assert_eq!(
            s,
            vec![
                SecureSenderEntry {
                    address: ia("1.1.16")?,
                    sequence: 0
                },
                SecureSenderEntry {
                    address: ia("1.1.30")?,
                    sequence: 0
                },
            ]
        );
        assert_eq!(
            sender_table_bytes(&s),
            vec![0x11, 0x10, 0, 0, 0, 0, 0, 0, 0x11, 0x1e, 0, 0, 0, 0, 0, 0]
        );
        // One telegram holds 26 entries at PID_MAX_APDU_LENGTH 233.
        assert_eq!(211 / SecureSenderEntry::LEN, 26);
        Ok(())
    }

    #[test]
    fn test_unconfirmed_flags_lists_values_ets_never_wrote() {
        let mut readback = SecurityReadback {
            go_flags: Some(vec![0x00, 0x03, 0x01, 0x00, 0x02, 0x83]),
            ..Default::default()
        };
        assert_eq!(
            readback.unconfirmed_flags(),
            vec![(3, 0x01), (5, 0x02), (6, 0x83)]
        );
        // They still count as secured (any non-zero octet).
        assert_eq!(
            readback.secured_objects(),
            Some(BTreeSet::from([2, 3, 5, 6]))
        );
        let note = unconfirmed_flags_note(&readback.unconfirmed_flags()).unwrap_or_default();
        assert!(note.contains("3 group object(s)"), "{note}");
        assert!(note.contains("3: 0x01, 5: 0x02, 6: 0x83"), "{note}");
        assert!(!note.contains("more"), "{note}");

        // Only confirmed values: no note. Not read: nothing to report.
        readback.go_flags = Some(vec![0x00, 0x03, 0x03]);
        assert!(readback.unconfirmed_flags().is_empty());
        assert_eq!(unconfirmed_flags_note(&readback.unconfirmed_flags()), None);
        readback.go_flags = None;
        assert!(readback.unconfirmed_flags().is_empty());

        // Long lists are cut at eight.
        let many: Vec<(u16, u8)> = (1..=10).map(|o| (o, 0x01)).collect();
        let note = unconfirmed_flags_note(&many).unwrap_or_default();
        assert!(note.contains("8: 0x01 and 2 more"), "{note}");
    }

    #[test]
    fn test_build_security_program_writes_only_confirmed_flag_values() -> TestResult {
        let program = build_security_program(
            "1.1.1".parse()?,
            &[],
            6,
            &BTreeSet::from([2, 5]),
            &BTreeSet::new(),
            &HashMap::new(),
        )?;
        assert_eq!(program.go_flags, vec![0x00, 0x03, 0x00, 0x00, 0x03, 0x00]);
        assert!(
            program
                .go_flags
                .iter()
                .all(|f| *f == GO_FLAGS_PLAIN || *f == GO_FLAGS_SECURE)
        );
        Ok(())
    }

    #[test]
    fn test_decode_sender_table_inverts_the_writer() -> TestResult {
        // The confirmed element of 1.1.16 (sender 1.1.5), then a zero element
        // (unused slot) and a partial trailing element: both are ignored.
        let mut bytes = vec![0x11, 0x05, 0x00, 0x40, 0x10, 0x2e, 0xa9, 0xce];
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&[0x11, 0x10, 0x00]);
        let entries = decode_sender_table(&bytes);
        assert_eq!(
            entries,
            vec![SecureSenderEntry {
                address: ia("1.1.5")?,
                sequence: 275_149_400_526
            }]
        );
        assert_eq!(sender_table_bytes(&entries), bytes[..8].to_vec());
        Ok(())
    }

    #[test]
    fn test_secured_senders_keeps_the_recorded_table() -> TestResult {
        let mut model = s3_model()?;
        // 1.1.5 was adopted with 1.1.16 (derived from the links too) and 1.1.77
        // (a sender the model does not describe) in its PID 54.
        let device = model
            .devices
            .get_mut(&ia("1.1.5")?)
            .ok_or("1.1.5 in the model")?;
        let security = device.device.security.as_mut().ok_or("security")?;
        security.secure_senders = vec![
            bussard_model::schema::SecureSender {
                address: ia("1.1.77")?,
                sequence: 99,
            },
            bussard_model::schema::SecureSender {
                address: ia("1.1.16")?,
                sequence: 12,
            },
            bussard_model::schema::SecureSender {
                address: ia("1.1.5")?,
                sequence: 1,
            },
        ];
        let s = secured_senders(
            Some(&model),
            ia("1.1.5")?,
            &HashMap::new(),
            &HashMap::new(),
            &[],
        );
        assert_eq!(
            s,
            vec![
                // Derived from the links: the derived sequence wins.
                SecureSenderEntry {
                    address: ia("1.1.16")?,
                    sequence: 0
                },
                // Recorded only: kept with its recorded sequence.
                SecureSenderEntry {
                    address: ia("1.1.77")?,
                    sequence: 99
                },
            ]
        );
        Ok(())
    }
}
