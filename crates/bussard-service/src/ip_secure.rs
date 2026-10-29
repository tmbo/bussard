//! KNXnet/IP Secure commissioning of a KNX IP interface without ETS (issue
//! #398): `bussard interface secure on|off <address>` and the MCP tool share
//! everything here.
//!
//! # The sequences
//!
//! Both follow the ETS captures of 1.1.200 (Jung IPS 300 SREG, 2026-10-26,
//! decoded with `tools/knxtrace`; the property layouts are documented in
//! [`bussard_mgmt::ip_secure`]).
//!
//! **On** (`ip-1-1-200-activate-secure.pcapng`), over a plain tunnel to a
//! device in factory state, one management connection:
//!
//! 1. under the FDSK: `PID_SECURITY_MODE` on, then `PID_TOOL_KEY`; the
//!    confirmation comes under the new tool key;
//! 2. under the tool key: `PID_SEQUENCE_NUMBER_SENDING`, routing not secured,
//!    `PID_DEVICE_AUTHENTICATION_CODE`, `PID_PASSWORD_HASHES` (count, then
//!    users 1..n), device management secured, `PID_TUNNELLING_USERS` (count,
//!    then the entries), tunnelling secured, a master reset (erase code 1).
//!
//! ETS also rewrites the `[knxnet]` table (PIDs 51, 53, 55, 66, 67, 76) in the
//! same session; bussard leaves that to `bussard apply`, and the model has no
//! routing multicast address or TTL to write.
//!
//! **Off**: the ETS deactivation ran inside a KNXnet/IP Secure session that a
//! capture cannot decrypt (`ip-1-1-200-deactivate-secure.pcapng`); the plain
//! lengths of its frames show, under the tool key, three secured-family
//! commands, the security mode command, a 16-octet write, a master reset
//! (and three writes whose PIDs the lengths do not name). Its second part
//! (`-part-2`, decoded) runs under the FDSK: the three families off, a master
//! reset. bussard runs:
//!
//! 1. under the tool key: device management, tunnelling and routing not
//!    secured, `PID_SECURITY_MODE` off, `PID_TOOL_KEY` back to the FDSK, a
//!    master reset;
//! 2. after the restart, under the FDSK on a fresh connection: the three
//!    families off again and a master reset, as the decoded part 2 does.
//!
//! # Credentials
//!
//! Every credential comes from the key store (`bussard.keys`) and new ones go
//! there; the model never holds one. `on` takes the device's FDSK, its tool
//! key, device authentication code and management password, and the
//! tunnelling users whose address is in the `[knxnet]` table's `tunnels`;
//! whatever is missing is generated and saved to the store **before** the
//! first write, so a crash leaves a store that matches the device or the
//! factory state. `off` drops the tool key from the store (the device is back
//! on its FDSK) only after the device verified on the FDSK. Recovery from any
//! state: the device's factory reset (its FDSK is always in the store) and
//! `bussard keys import` of an ETS export, see `docs/explanation/safety.md`.

use std::collections::BTreeMap;
use std::path::Path;

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::ip_secure::{
    self as wire, KEY_OCTETS, OT_KNXNET_IP_PARAMETER, PID_DEVICE_AUTHENTICATION_CODE,
    PID_PASSWORD_HASHES, PID_SECURED_SERVICE_FAMILIES, PID_TUNNELLING_USERS, family,
};
use bussard_mgmt::property_ext::{
    OT_SECURITY, PID_SECURITY_MODE, PID_SEQUENCE_NUMBER_SENDING, PID_TOOL_KEY,
};
use bussard_model::IndividualAddress;
use bussard_project::KeyStore;
use bussard_project::keystore::StoreInterface;
use bussard_secure::{Key16, Password, Sequence, salt};
use sha2::{Digest, Sha256};

/// Which way the switch goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Switch {
    /// Switch KNXnet/IP Secure on.
    On,
    /// Switch KNXnet/IP Secure off.
    Off,
}

impl std::fmt::Display for Switch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Switch::On => "on",
            Switch::Off => "off",
        })
    }
}

/// The key a step's request travels under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// The factory key (FDSK).
    Fdsk,
    /// The tool key.
    Tool,
}

/// One operation of a switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `PID_SECURITY_MODE` (type 17 PID 51) on or off.
    SecurityMode(bool),
    /// `PID_TOOL_KEY` (type 17 PID 56): the tool key (`on`) or the FDSK (`off`).
    ToolKey,
    /// `PID_SEQUENCE_NUMBER_SENDING` (type 17 PID 59), from the clock.
    SequenceNumber,
    /// `PID_SECURED_SERVICE_FAMILIES` (type 11 PID 94) for one family.
    SecuredFamily {
        /// The KNXnet/IP service family id.
        family: u8,
        /// Secured or not.
        on: bool,
    },
    /// `PID_DEVICE_AUTHENTICATION_CODE` (type 11 PID 92).
    DeviceAuthentication,
    /// `PID_PASSWORD_HASHES` (type 11 PID 93), users 1..n.
    PasswordHashes,
    /// `PID_TUNNELLING_USERS` (type 11 PID 97).
    TunnellingUsers,
    /// `A_Restart` master reset, erase code 1.
    MasterReset,
}

/// A step and the key its request goes under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    /// The operation.
    pub step: Step,
    /// The key.
    pub phase: Phase,
}

/// The secrets one switch writes. Never printed: `Debug` is redacted.
struct Secrets {
    fdsk: Key16,
    tool_key: Key16,
    device_auth: Option<Key16>,
    /// The password keys of users 1..n (1 the management user).
    user_keys: Vec<Key16>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("users", &self.user_keys.len())
            .finish_non_exhaustive()
    }
}

/// Why a switch cannot be planned or run.
#[derive(Debug, thiserror::Error)]
pub enum IpSecureError {
    /// The key store has no factory key for the device.
    #[error(
        "the key store has no FDSK (factory key) for {0}: import an ETS keyring export that \
         carries it (`bussard keys import`), or record it from the device certificate"
    )]
    NoFdsk(IndividualAddress),
    /// `off` needs the tool key the device holds.
    #[error(
        "the key store has no tool key for {0}, so bussard cannot reach its secured management; \
         import the ETS keyring export (`bussard keys import`), or factory-reset the device"
    )]
    NoToolKey(IndividualAddress),
    /// The model plans no tunnelling address for the interface.
    #[error(
        "devices/{0}.toml has no tunnelling addresses in its [knxnet] table; KNXnet/IP Secure \
         needs a tunnelling user per address"
    )]
    NoTunnels(IndividualAddress),
    /// More users than one property write carries.
    #[error("{0} tunnelling addresses; one PID 93/97 write carries at most 14 users")]
    TooManyTunnels(usize),
    /// A `[knxnet]` tunnel address the interface does not use for tunnelling
    /// (its PID 53 entry is not in `PID_TUNNELLING_ADDRESSES`, issue #520).
    #[error(
        "{address} (entry {slot} of {target}'s additional individual addresses) is not one of \
         its tunnelling addresses: PID_TUNNELLING_ADDRESSES (79) reads {table:?} (0 the \
         interface's own address, n the n-th additional address); a tunnelling user on it could \
         never connect"
    )]
    NotATunnellingAddress {
        /// The interface.
        target: IndividualAddress,
        /// The tunnel address.
        address: IndividualAddress,
        /// Its 1-based PID 53 entry.
        slot: u8,
        /// PID 79 as read.
        table: Vec<u8>,
    },
    /// Two tunnelling addresses share a user id, or a user id is out of range.
    #[error("the key store's tunnelling users for {target} are not usable: {why}")]
    BadUsers {
        /// The interface.
        target: IndividualAddress,
        /// What is wrong.
        why: String,
    },
    /// A random credential could not be drawn.
    #[error("drawing a random credential: {0}")]
    Random(String),
    /// A management exchange failed.
    #[error(transparent)]
    Mgmt(#[from] bussard_mgmt::MgmtError),
    /// The master reset failed.
    #[error(transparent)]
    Write(#[from] bussard_mgmt::load::WriteError),
}

/// The plan of one switch: the steps, what the key store gains, and the
/// secrets (kept private).
#[derive(Debug)]
pub struct SwitchPlan {
    /// The interface.
    pub target: IndividualAddress,
    /// On or off.
    pub switch: Switch,
    /// The steps in wire order. For `off`, the steps after the first master
    /// reset run on a second connection, after the restart.
    pub steps: Vec<PlannedStep>,
    /// The `PID_TUNNELLING_USERS` entries, `(user id, address index)`, the
    /// index pointing into `PID_TUNNELLING_ADDRESSES` (PID 79). Planned for
    /// the identity table `1..n`; the run reads PID 79 first and
    /// [resolves](Self::resolve_tunnel_users) them against it (issue #520).
    pub tunnel_users: Vec<(u8, u8)>,
    /// The tunnelling users by address: `(user id, 1-based PID 53 entry,
    /// the address)`, user id order.
    pub tunnel_slots: Vec<(u8, u8, IndividualAddress)>,
    /// What the run found out about the plan (PID 79 as read).
    pub notes: Vec<String>,
    /// Credentials the plan generated (names, never values); the key store
    /// gains them before the first write.
    pub generated: Vec<String>,
    /// The key store with the generated credentials added, when it changed.
    store_update: Option<KeyStore>,
    secrets: Secrets,
}

impl SwitchPlan {
    /// Resolves the `PID_TUNNELLING_USERS` entries against `table`, the
    /// interface's `PID_TUNNELLING_ADDRESSES` (PID 79) as read: each user's
    /// index becomes the 1-based position of its PID 53 entry in the table
    /// (KNX IP Secure 3/8/9 §2.3.1.8.3, Device Management 3/8/3 §2.5.29,
    /// issue #520). `None` (the device does not serve PID 79) keeps the
    /// identity mapping and records a note.
    ///
    /// # Errors
    ///
    /// [`IpSecureError::NotATunnellingAddress`] when a tunnel's PID 53 entry
    /// is not in the table.
    pub fn resolve_tunnel_users(&mut self, table: Option<&[u8]>) -> Result<(), IpSecureError> {
        let Some(table) = table else {
            self.notes.push(
                "the interface does not serve PID_TUNNELLING_ADDRESSES (79): the tunnelling users \
                 assume its tunnelling addresses are the additional addresses 1..n in order"
                    .to_string(),
            );
            return Ok(());
        };
        let mut users = Vec::with_capacity(self.tunnel_slots.len());
        for &(user, slot, address) in &self.tunnel_slots {
            let Some(position) = table.iter().position(|&id| id == slot) else {
                return Err(IpSecureError::NotATunnellingAddress {
                    target: self.target,
                    address,
                    slot,
                    table: table.to_vec(),
                });
            };
            users.push((user, u8::try_from(position + 1).unwrap_or(u8::MAX)));
        }
        users.sort_unstable();
        if users != self.tunnel_users {
            self.notes.push(format!(
                "PID_TUNNELLING_ADDRESSES (79) reads {table:?}: tunnelling users {} instead of \
                 the planned {}",
                pairs(&users),
                pairs(&self.tunnel_users)
            ));
        }
        self.tunnel_users = users;
        Ok(())
    }

    /// Whether the key store must be saved before the first write.
    pub fn changes_store(&self) -> bool {
        self.store_update.is_some()
    }

    /// Saves the key store with the generated credentials, if any, in `dir`.
    ///
    /// # Errors
    ///
    /// The store cannot be written.
    pub fn save_store(
        &self,
        dir: &Path,
        password: &str,
    ) -> Result<bool, bussard_project::keystore::KeyStoreError> {
        match &self.store_update {
            Some(store) => store.save(dir, password).map(|_| true),
            None => Ok(false),
        }
    }

    /// The device's FDSK, for the factory-key connection.
    pub fn fdsk(&self) -> Key16 {
        self.secrets.fdsk.clone()
    }

    /// The tool key the device holds after `on` (or before `off`).
    pub fn tool_key(&self) -> Key16 {
        self.secrets.tool_key.clone()
    }

    /// The steps of the first connection: everything up to and including the
    /// first master reset.
    pub fn first_connection(&self) -> &[PlannedStep] {
        let end = self
            .steps
            .iter()
            .position(|s| s.step == Step::MasterReset)
            .map_or(self.steps.len(), |i| i + 1);
        &self.steps[..end]
    }

    /// The steps after the first master reset (`off`'s factory-key pass).
    pub fn second_connection(&self) -> &[PlannedStep] {
        &self.steps[self.first_connection().len()..]
    }

    /// The key the first connection opens with: the FDSK for `on` (a device
    /// in factory state), the tool key for `off`.
    pub fn opening_key(&self) -> Key16 {
        match self.switch {
            Switch::On => self.fdsk(),
            Switch::Off => self.tool_key(),
        }
    }

    /// One line per step, as the plan and `--dry-run` print it. No value of
    /// key material appears.
    pub fn lines(&self) -> Vec<String> {
        self.steps.iter().map(|s| self.describe(s)).collect()
    }

    fn describe(&self, planned: &PlannedStep) -> String {
        let key = match planned.phase {
            Phase::Fdsk => "FDSK",
            Phase::Tool => "tool key",
        };
        let what = match &planned.step {
            Step::SecurityMode(on) => format!(
                "security mode {} (type 17 PID 51)",
                if *on { "on" } else { "off" }
            ),
            Step::ToolKey => match self.switch {
                Switch::On => "tool key (type 17 PID 56)".to_string(),
                Switch::Off => "tool key back to the FDSK (type 17 PID 56)".to_string(),
            },
            Step::SequenceNumber => "send sequence (type 17 PID 59)".to_string(),
            Step::SecuredFamily { family, on } => format!(
                "{} {} (type 11 PID 94)",
                family_name(*family),
                if *on { "secured" } else { "not secured" }
            ),
            Step::DeviceAuthentication => "device authentication code (type 11 PID 92)".to_string(),
            Step::PasswordHashes => format!(
                "password hashes of users 1 to {} (type 11 PID 93)",
                self.secrets.user_keys.len()
            ),
            Step::TunnellingUsers => {
                format!(
                    "tunnelling users {} (type 11 PID 97)",
                    pairs(&self.tunnel_users)
                )
            }
            Step::MasterReset => "master reset (erase code 1)".to_string(),
        };
        format!("{what}, under the {key}")
    }

    /// The property records of the plan, for `--dump-images` (`plan.json`,
    /// `system: "ip-secure"`), in the shape `tools/knxtrace` compares against
    /// an ETS capture: object type, instance, PID, start element, length, and
    /// the value as hex or, for key material, its SHA-256 only.
    pub fn records(&self) -> Vec<PlanRecordStep> {
        let mut out = Vec::new();
        for (i, planned) in self.steps.iter().enumerate() {
            let records = self.step_records(planned);
            out.push(PlanRecordStep {
                index: i + 1,
                label: self.describe(planned),
                phase: planned.phase,
                properties: records,
            });
        }
        out
    }

    fn step_records(&self, planned: &PlannedStep) -> Vec<PlanRecord> {
        let phase = planned.phase;
        let record = |object_type: u16, pid: u16, start: Option<u16>, value: Value| PlanRecord {
            object_type,
            instance: 1,
            pid,
            start_element: start,
            length: value.len(),
            data: value.hex(),
            sha256: value.sha256(),
            phase,
        };
        match &planned.step {
            Step::SecurityMode(on) => vec![record(
                OT_SECURITY,
                PID_SECURITY_MODE,
                None,
                Value::Plain(wire::security_mode_command(*on).to_vec()),
            )],
            Step::ToolKey => {
                let key = match self.switch {
                    Switch::On => &self.secrets.tool_key,
                    Switch::Off => &self.secrets.fdsk,
                };
                vec![record(
                    OT_SECURITY,
                    PID_TOOL_KEY,
                    Some(1),
                    Value::Secret(key.bytes().to_vec()),
                )]
            }
            Step::SequenceNumber => vec![record(
                OT_SECURITY,
                PID_SEQUENCE_NUMBER_SENDING,
                Some(1),
                Value::Unknown(wire::SEQUENCE_OCTETS),
            )],
            Step::SecuredFamily { family, on } => vec![record(
                OT_KNXNET_IP_PARAMETER,
                PID_SECURED_SERVICE_FAMILIES,
                None,
                Value::Plain(wire::secured_family_command(*family, *on).to_vec()),
            )],
            Step::DeviceAuthentication => vec![record(
                OT_KNXNET_IP_PARAMETER,
                PID_DEVICE_AUTHENTICATION_CODE,
                Some(1),
                match &self.secrets.device_auth {
                    Some(key) => Value::Secret(key.bytes().to_vec()),
                    None => Value::Unknown(KEY_OCTETS),
                },
            )],
            Step::PasswordHashes => {
                let count = u16::try_from(self.secrets.user_keys.len()).unwrap_or(0);
                let mut all = Vec::with_capacity(self.secrets.user_keys.len() * KEY_OCTETS);
                for key in &self.secrets.user_keys {
                    all.extend_from_slice(key.bytes());
                }
                vec![
                    // knxtrace redacts every PID 93 value, the count too, so
                    // both sides compare it by hash.
                    record(
                        OT_KNXNET_IP_PARAMETER,
                        PID_PASSWORD_HASHES,
                        Some(0),
                        Value::Secret(count.to_be_bytes().to_vec()),
                    ),
                    record(
                        OT_KNXNET_IP_PARAMETER,
                        PID_PASSWORD_HASHES,
                        Some(1),
                        Value::Secret(all),
                    ),
                ]
            }
            Step::TunnellingUsers => {
                let count = u16::try_from(self.tunnel_users.len()).unwrap_or(0);
                vec![
                    record(
                        OT_KNXNET_IP_PARAMETER,
                        PID_TUNNELLING_USERS,
                        Some(0),
                        Value::Plain(count.to_be_bytes().to_vec()),
                    ),
                    record(
                        OT_KNXNET_IP_PARAMETER,
                        PID_TUNNELLING_USERS,
                        Some(1),
                        Value::Plain(
                            self.tunnel_users
                                .iter()
                                .flat_map(|&(u, i)| [u, i])
                                .collect(),
                        ),
                    ),
                ]
            }
            Step::MasterReset => Vec::new(),
        }
    }
}

/// A property value in a dumped plan.
enum Value {
    /// Shown as hex.
    Plain(Vec<u8>),
    /// Key material: only its SHA-256.
    Secret(Vec<u8>),
    /// Decided at run time (the clock-seeded sequence): only its length.
    Unknown(usize),
}

impl Value {
    fn len(&self) -> usize {
        match self {
            Value::Plain(b) | Value::Secret(b) => b.len(),
            Value::Unknown(n) => *n,
        }
    }

    fn hex(&self) -> Option<String> {
        match self {
            Value::Plain(b) => Some(hex(b)),
            _ => None,
        }
    }

    fn sha256(&self) -> Option<String> {
        match self {
            Value::Secret(b) => Some(hex(&Sha256::digest(b))),
            _ => None,
        }
    }
}

/// `user->index` pairs, space-separated.
fn pairs(users: &[(u8, u8)]) -> String {
    users
        .iter()
        .map(|(u, i)| format!("{u}->{i}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// One step of a dumped plan (`plan.json`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlanRecordStep {
    /// 1-based.
    pub index: usize,
    /// What the step does.
    pub label: String,
    /// The key its request goes under.
    pub phase: Phase,
    /// The property writes (none for the master reset).
    pub properties: Vec<PlanRecord>,
}

/// One property write of a dumped plan, in the shape knxtrace reads.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlanRecord {
    /// The interface object type.
    pub object_type: u16,
    /// The instance (1).
    pub instance: u16,
    /// The property id.
    pub pid: u16,
    /// The start element; `None` for a function-property command.
    pub start_element: Option<u16>,
    /// The value length in octets.
    pub length: usize,
    /// The value as hex, when it is not key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// The value's SHA-256, for key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The key the write goes under.
    pub phase: Phase,
}

/// The name of a KNXnet/IP service family.
pub fn family_name(family: u8) -> &'static str {
    match family {
        family::DEVICE_MANAGEMENT => "device management",
        family::TUNNELLING => "tunnelling",
        family::ROUTING => "routing",
        _ => "service family",
    }
}

/// A random password: 24 hexadecimal characters (96 bits), Latin-1 safe.
fn random_password() -> Result<Password, IpSecureError> {
    let bytes =
        bussard_secure::random_bytes::<12>().map_err(|e| IpSecureError::Random(e.to_string()))?;
    Ok(Password::new(hex(&bytes)))
}

/// Plans `on` for `target` from the key store and the `[knxnet]` table's
/// tunnelling addresses (slot order).
///
/// The tunnelling users are the store's `Tunneling` interfaces whose address
/// is in `tunnels`; an address without one gets user id `slot + 1` (the ETS
/// convention: users 2.. for slots 1..) and a generated password. The device
/// authentication code, the management password and the tool key are taken
/// from the store, else generated. Generated credentials are added to a copy
/// of the store that [`SwitchPlan::save_store`] writes.
///
/// # Errors
///
/// No FDSK, no tunnelling address, more than 14 users, clashing user ids, or
/// no randomness.
pub fn plan_on(
    store: &KeyStore,
    target: IndividualAddress,
    tunnels: &[IndividualAddress],
) -> Result<SwitchPlan, IpSecureError> {
    let device = store.devices.get(&target).cloned().unwrap_or_default();
    let fdsk = device.fdsk.clone().ok_or(IpSecureError::NoFdsk(target))?;
    if tunnels.is_empty() {
        return Err(IpSecureError::NoTunnels(target));
    }
    if tunnels.len() > 14 {
        return Err(IpSecureError::TooManyTunnels(tunnels.len()));
    }
    let mut updated = store_clone(store);
    let mut generated = Vec::new();
    let entry = updated.devices.entry(target).or_default();
    let tool_key = match &device.tool_key {
        Some(key) => key.clone(),
        None => {
            let key = Key16::new(
                bussard_secure::random_bytes::<16>()
                    .map_err(|e| IpSecureError::Random(e.to_string()))?,
            );
            entry.tool_key = Some(key.clone());
            generated.push("tool key".to_string());
            key
        }
    };
    let host_code = store
        .interfaces
        .iter()
        .find(|i| i.host == Some(target) && i.authentication.is_some())
        .and_then(|i| i.authentication.clone());
    let auth = match device.authentication.clone().or(host_code) {
        Some(code) => code,
        None => {
            let code = random_password()?;
            generated.push("device authentication code".to_string());
            code
        }
    };
    entry.authentication = Some(auth.clone());
    let management = match &device.management_password {
        Some(pw) => pw.clone(),
        None => {
            let pw = random_password()?;
            entry.management_password = Some(pw.clone());
            generated.push("management password".to_string());
            pw
        }
    };

    // The tunnelling users, by slot.
    let mut users: BTreeMap<u8, (u8, Password, IndividualAddress)> = BTreeMap::new();
    for (slot0, ia) in tunnels.iter().enumerate() {
        let slot = u8::try_from(slot0 + 1).unwrap_or(u8::MAX);
        let known = updated.interfaces.iter_mut().find(|i| {
            i.ia == *ia
                && i.interface_type.eq_ignore_ascii_case("tunneling")
                && i.host.is_none_or(|h| h == target)
        });
        let (user_id, password) = match known {
            Some(iface) if iface.password.is_some() => {
                if iface.authentication.is_none() {
                    iface.authentication = Some(auth.clone());
                }
                iface.host = Some(target);
                (
                    iface.user_id,
                    iface.password.clone().unwrap_or_else(|| Password::new("")),
                )
            }
            _ => {
                let user_id = slot.saturating_add(1);
                let password = random_password()?;
                updated.interfaces.retain(|i| {
                    !(i.ia == *ia && i.interface_type.eq_ignore_ascii_case("tunneling"))
                });
                updated.interfaces.push(StoreInterface {
                    interface_type: "Tunneling".to_string(),
                    ia: *ia,
                    host: Some(target),
                    user_id,
                    password: Some(password.clone()),
                    authentication: Some(auth.clone()),
                    gas: Vec::new(),
                });
                generated.push(format!("password of tunnelling user {user_id} ({ia})"));
                (user_id, password)
            }
        };
        if user_id < 2 {
            return Err(IpSecureError::BadUsers {
                target,
                why: format!("{ia} has user id {user_id}; tunnelling users start at 2"),
            });
        }
        if users.insert(user_id, (slot, password, *ia)).is_some() {
            return Err(IpSecureError::BadUsers {
                target,
                why: format!("user id {user_id} is used by two tunnelling addresses"),
            });
        }
    }
    // PID 93 holds users 1..=max: every id in between needs a password.
    let max = users.keys().copied().max().unwrap_or(1);
    let mut user_keys = vec![management.derive(salt::USER_PASSWORD)];
    for id in 2..=max {
        let Some((_, password, _)) = users.get(&id) else {
            return Err(IpSecureError::BadUsers {
                target,
                why: format!(
                    "user ids run to {max}, but no tunnelling address has user id {id} (PID 93 \
                     holds every user from 1 up)"
                ),
            });
        };
        user_keys.push(password.derive(salt::USER_PASSWORD));
    }
    // Planned for the identity PID 79 table; the run resolves them (#520).
    let tunnel_users: Vec<(u8, u8)> = users.iter().map(|(&u, (slot, _, _))| (u, *slot)).collect();
    let tunnel_slots: Vec<(u8, u8, IndividualAddress)> = users
        .iter()
        .map(|(&u, (slot, _, ia))| (u, *slot, *ia))
        .collect();
    let changed = !generated.is_empty() || !same_credentials(store, &updated, target);
    let steps = on_steps();
    Ok(SwitchPlan {
        target,
        switch: Switch::On,
        steps,
        tunnel_users,
        tunnel_slots,
        notes: Vec::new(),
        generated,
        store_update: changed.then_some(updated),
        secrets: Secrets {
            fdsk,
            tool_key,
            device_auth: Some(auth.derive(salt::DEVICE_AUTHENTICATION_CODE)),
            user_keys,
        },
    })
}

/// Plans `off` for `target`: needs the tool key the device holds and its
/// FDSK.
///
/// # Errors
///
/// No tool key or no FDSK in the store.
pub fn plan_off(store: &KeyStore, target: IndividualAddress) -> Result<SwitchPlan, IpSecureError> {
    let device = store.devices.get(&target).cloned().unwrap_or_default();
    let tool_key = device
        .tool_key
        .clone()
        .ok_or(IpSecureError::NoToolKey(target))?;
    let fdsk = device.fdsk.clone().ok_or(IpSecureError::NoFdsk(target))?;
    Ok(SwitchPlan {
        target,
        switch: Switch::Off,
        steps: off_steps(),
        tunnel_users: Vec::new(),
        tunnel_slots: Vec::new(),
        notes: Vec::new(),
        generated: Vec::new(),
        store_update: None,
        secrets: Secrets {
            fdsk,
            tool_key,
            device_auth: None,
            user_keys: Vec::new(),
        },
    })
}

/// The key store after a verified `off`: the device keeps its FDSK, serial
/// and KNXnet/IP credentials (an `on` reuses them) and loses its tool key.
pub fn store_after_off(store: &KeyStore, target: IndividualAddress) -> KeyStore {
    let mut updated = store_clone(store);
    if let Some(device) = updated.devices.get_mut(&target) {
        device.tool_key = None;
    }
    updated
}

/// The steps of `on`, in the ETS order.
fn on_steps() -> Vec<PlannedStep> {
    use Phase::{Fdsk, Tool};
    let p = |step, phase| PlannedStep { step, phase };
    vec![
        p(Step::SecurityMode(true), Fdsk),
        p(Step::ToolKey, Fdsk),
        p(Step::SequenceNumber, Tool),
        p(
            Step::SecuredFamily {
                family: family::ROUTING,
                on: false,
            },
            Tool,
        ),
        p(Step::DeviceAuthentication, Tool),
        p(Step::PasswordHashes, Tool),
        p(
            Step::SecuredFamily {
                family: family::DEVICE_MANAGEMENT,
                on: true,
            },
            Tool,
        ),
        p(Step::TunnellingUsers, Tool),
        p(
            Step::SecuredFamily {
                family: family::TUNNELLING,
                on: true,
            },
            Tool,
        ),
        p(Step::MasterReset, Tool),
    ]
}

/// The steps of `off`: the tool-key pass, then the factory-key pass.
fn off_steps() -> Vec<PlannedStep> {
    use Phase::{Fdsk, Tool};
    let p = |step, phase| PlannedStep { step, phase };
    let families = |phase: Phase| {
        [
            family::ROUTING,
            family::DEVICE_MANAGEMENT,
            family::TUNNELLING,
        ]
        .into_iter()
        .map(move |family| p(Step::SecuredFamily { family, on: false }, phase))
    };
    let mut steps: Vec<PlannedStep> = families(Tool).collect();
    steps.push(p(Step::SecurityMode(false), Tool));
    steps.push(p(Step::ToolKey, Tool));
    steps.push(p(Step::MasterReset, Fdsk));
    steps.extend(families(Fdsk));
    steps.push(p(Step::MasterReset, Fdsk));
    steps
}

/// Whether the store's credentials for `target` are unchanged in `updated`.
fn same_credentials(store: &KeyStore, updated: &KeyStore, target: IndividualAddress) -> bool {
    let dev = |s: &KeyStore| {
        s.devices.get(&target).map(|d| {
            (
                d.tool_key.as_ref().map(|k| *k.bytes()),
                d.authentication.clone(),
                d.management_password.clone(),
            )
        })
    };
    let ifaces = |s: &KeyStore| {
        s.interfaces
            .iter()
            .filter(|i| i.host == Some(target))
            .map(|i| {
                (
                    i.ia,
                    i.user_id,
                    i.password.clone(),
                    i.authentication.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    dev(store) == dev(updated) && ifaces(store) == ifaces(updated)
}

/// A deep copy of the store (it has no `Clone` of its own).
fn store_clone(store: &KeyStore) -> KeyStore {
    KeyStore {
        project: store.project.clone(),
        created: store.created.clone(),
        backbone: store.backbone.clone(),
        interfaces: store.interfaces.clone(),
        devices: store.devices.clone(),
        group_keys: store.group_keys.clone(),
    }
}

/// What one connection of a switch did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionReport {
    /// Steps sent and confirmed.
    pub done: usize,
    /// The restart's process time (seconds) when the connection ended with
    /// a master reset.
    pub restart_seconds: Option<u16>,
}

/// Runs `steps` on one management connection, in order.
///
/// The connection must be open under the step's first key: the FDSK for
/// `on`, the tool key for `off`'s first pass, the FDSK for its second. A
/// tool-key step switches the connection to the key it writes. `progress` is
/// called with each step's line before it is sent.
///
/// # Errors
///
/// The first failing step: the device may hold everything before it.
pub async fn run_steps<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &SwitchPlan,
    steps: &[PlannedStep],
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<ConnectionReport, IpSecureError> {
    let mut report = ConnectionReport::default();
    for planned in steps {
        progress(&plan.describe(planned));
        match &planned.step {
            Step::SecurityMode(on) => wire::set_security_mode(l4, *on).await?,
            Step::ToolKey => {
                let key = match plan.switch {
                    Switch::On => &plan.secrets.tool_key,
                    Switch::Off => &plan.secrets.fdsk,
                };
                wire::write_tool_key(l4, key).await?;
            }
            Step::SequenceNumber => {
                wire::write_sequence_number(l4, Sequence::seed().value()).await?;
            }
            Step::SecuredFamily { family, on } => {
                wire::set_secured_family(l4, *family, *on).await?;
            }
            Step::DeviceAuthentication => {
                if let Some(key) = &plan.secrets.device_auth {
                    wire::write_device_authentication(l4, key).await?;
                }
            }
            Step::PasswordHashes => {
                wire::write_password_hashes(l4, &plan.secrets.user_keys).await?;
            }
            Step::TunnellingUsers => {
                wire::write_tunnelling_users(l4, &plan.tunnel_users).await?;
            }
            Step::MasterReset => {
                let response = bussard_mgmt::load::master_reset(l4, 1, 0).await?;
                report.restart_seconds = Some(response.process_time_s);
            }
        }
        report.done += 1;
    }
    Ok(report)
}

/// What the read-back after a switch found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// The security mode the device reports, when it answered with one.
    pub security_mode: Option<bool>,
    /// `PID_TUNNELLING_USERS` as read back (`on` only).
    pub tunnel_users: Option<Vec<(u8, u8)>>,
    /// What does not match the plan; empty when verified.
    pub mismatches: Vec<String>,
}

impl Verification {
    /// Whether everything read back matches.
    pub fn verified(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// Reads back what a switch set, on a connection opened under the key the
/// device should now hold (the tool key after `on`, the FDSK after `off`):
/// the security mode and, after `on`, the tunnelling users. A connection
/// that opens and syncs under that key is itself part of the evidence.
///
/// # Errors
///
/// A failing read.
pub async fn verify<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &SwitchPlan,
) -> Result<Verification, IpSecureError> {
    let want_on = plan.switch == Switch::On;
    let mode = wire::read_security_mode(l4).await?;
    let mut mismatches = Vec::new();
    match mode {
        Some(on) if on != want_on => mismatches.push(format!(
            "the security mode reads {}, expected {}",
            if on { "on" } else { "off" },
            plan.switch
        )),
        None => mismatches.push("the security mode read returned no value".to_string()),
        _ => {}
    }
    let mut users = None;
    if want_on {
        let read = wire::read_tunnelling_users(l4).await?;
        if read != plan.tunnel_users {
            mismatches.push(format!(
                "PID 97 reads {:?}, expected {:?} (user id, address index)",
                read, plan.tunnel_users
            ));
        }
        users = Some(read);
    }
    Ok(Verification {
        security_mode: mode,
        tunnel_users: users,
        mismatches,
    })
}

/// The longest wait for a restart, whatever the device reports.
pub fn restart_wait(seconds: Option<u16>) -> std::time::Duration {
    std::time::Duration::from_secs(u64::from(seconds.unwrap_or(8)))
        .min(bussard_mgmt::load::MAX_RESTART_PROCESS_WAIT)
}

/// The steps' wire addresses, for tests and the oracle: `(object type, PID)`.
pub fn step_property(step: &Step) -> Option<(u16, u16)> {
    Some(match step {
        Step::SecurityMode(_) => (OT_SECURITY, PID_SECURITY_MODE),
        Step::ToolKey => (OT_SECURITY, PID_TOOL_KEY),
        Step::SequenceNumber => (OT_SECURITY, PID_SEQUENCE_NUMBER_SENDING),
        Step::SecuredFamily { .. } => (OT_KNXNET_IP_PARAMETER, PID_SECURED_SERVICE_FAMILIES),
        Step::DeviceAuthentication => (OT_KNXNET_IP_PARAMETER, PID_DEVICE_AUTHENTICATION_CODE),
        Step::PasswordHashes => (OT_KNXNET_IP_PARAMETER, PID_PASSWORD_HASHES),
        Step::TunnellingUsers => (OT_KNXNET_IP_PARAMETER, PID_TUNNELLING_USERS),
        Step::MasterReset => return None,
    })
}

/// The text a surface hashes into a plan digest: the target, the direction,
/// the step lines and the names of generated credentials. No value.
pub fn interface_digest_text(plan: &SwitchPlan) -> String {
    format!(
        "ip-secure {} {}\n{}\n{}",
        plan.target,
        plan.switch,
        plan.lines().join("\n"),
        plan.generated.join("\n")
    )
}

/// Where and how a switch connects.
#[derive(Debug, Clone)]
pub struct SwitchContext<'a> {
    /// The connection as the surface resolved it (gateway, secure tunnel).
    pub config: bussard_transport::ConnectionConfig,
    /// The write policy (the remote-gateway opt-in).
    pub policy: crate::WritePolicy,
    /// `--skip-address-check`.
    pub skip_address_check: bool,
    /// The model directory, where the key store lives.
    pub dir: &'a Path,
    /// The keyring password the key store is encrypted with.
    pub keystore_password: &'a str,
    /// How long to wait for a tunnel to come up.
    pub connect_wait: std::time::Duration,
}

/// What a switch did.
#[derive(Debug, Clone)]
pub struct SwitchOutcome {
    /// Whether the key store was written before the first write (`on` with
    /// generated credentials).
    pub store_saved_before: bool,
    /// The first connection.
    pub first: ConnectionReport,
    /// The factory-key pass of `off`.
    pub second: Option<ConnectionReport>,
    /// The gateway's KNXnet/IP Secure state after the switch, when the target
    /// is the gateway itself: whether tunnelling is secure-only.
    pub gateway_secure_only: Option<bool>,
    /// The read-back.
    pub verification: Verification,
    /// Whether the key store was updated after the verification (`off`).
    pub store_saved_after: bool,
}

impl SwitchOutcome {
    /// Whether the switch is verified: the read-back matches and the gateway,
    /// when it is the target, reports the expected tunnelling security.
    pub fn verified(&self, switch: Switch) -> bool {
        self.verification.verified()
            && self
                .gateway_secure_only
                .is_none_or(|secure| secure == (switch == Switch::On))
    }
}

/// Why a switch stopped.
#[derive(Debug, thiserror::Error)]
pub enum SwitchError {
    /// A management step or read failed; `stage` says where.
    #[error("{stage}: {source}")]
    Step {
        /// Which part of the switch.
        stage: &'static str,
        /// The failure.
        #[source]
        source: IpSecureError,
    },
    /// The bus could not be opened or a session not established.
    #[error("{stage}: {source}")]
    Service {
        /// Which part of the switch.
        stage: &'static str,
        /// The failure.
        #[source]
        source: crate::ServiceError,
    },
    /// The key store could not be written.
    #[error("{stage}: {source}")]
    Store {
        /// Which part of the switch.
        stage: &'static str,
        /// The failure.
        #[source]
        source: bussard_project::keystore::KeyStoreError,
    },
    /// The verification connection could not be configured.
    #[error("configuring the verification tunnel: {0}")]
    SecureConfig(#[from] crate::secure::SecureKeyError),
}

/// A `with_l4` body error: the service's or a step's.
enum BodyError {
    Service(crate::ServiceError),
    Step(IpSecureError),
}

impl From<crate::ServiceError> for BodyError {
    fn from(err: crate::ServiceError) -> Self {
        BodyError::Service(err)
    }
}

impl BodyError {
    fn at(self, stage: &'static str) -> SwitchError {
        match self {
            BodyError::Service(source) => SwitchError::Service { stage, source },
            BodyError::Step(source) => SwitchError::Step { stage, source },
        }
    }
}

/// The gateway's description, when the configuration names one and it
/// answers: its individual address and whether tunnelling is secure-only.
pub async fn probe_gateway(
    config: &bussard_transport::ConnectionConfig,
) -> Option<(Option<IndividualAddress>, bool)> {
    let gateway = config.gateway?;
    let probed = bussard_transport::discovery::describe_gateway_extended(
        gateway,
        std::time::Duration::from_secs(2),
    )
    .await
    .ok()?;
    Some((
        probed.individual_address.map(IndividualAddress::from_raw),
        probed.tunnelling_secure_only(),
    ))
}

/// Whether a session over `config` is secured through `target` itself: the
/// configuration carries KNXnet/IP Secure credentials, and the gateway
/// ([`probe_gateway`]) is `target` with secure-only tunnelling, so the
/// session is a secure one. The MCP server refuses a switch then: it would
/// end its own session.
pub fn secured_through(
    config: &bussard_transport::ConnectionConfig,
    probed: Option<(Option<IndividualAddress>, bool)>,
    target: IndividualAddress,
) -> bool {
    config.secure.is_some()
        && probed.is_some_and(|(gateway, secure_only)| secure_only && gateway == Some(target))
}

/// Opens the bus and waits for the tunnel.
async fn open(
    config: bussard_transport::ConnectionConfig,
    ctx: &SwitchContext<'_>,
    stage: &'static str,
) -> Result<crate::BusService, SwitchError> {
    let service = crate::BusService::open(config, ctx.policy)
        .map_err(|source| SwitchError::Service { stage, source })?;
    let _ = service.wait_connected(ctx.connect_wait).await;
    Ok(service)
}

/// Runs `steps` on one management connection opened under `key`. When they
/// write `PID_TUNNELLING_USERS`, the connection first reads
/// `PID_TUNNELLING_ADDRESSES` (PID 79) and resolves the users against it
/// (issue #520), before anything is written.
async fn connection(
    ctx: &SwitchContext<'_>,
    config: bussard_transport::ConnectionConfig,
    plan: &mut SwitchPlan,
    steps: &[PlannedStep],
    key: Key16,
    stage: &'static str,
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<ConnectionReport, SwitchError> {
    // The connection ends with the device's restart: a tunnel that tried to
    // re-establish itself through the rebooting interface would only delay
    // the next stage.
    let mut config = config;
    config.reconnect.budget = std::time::Duration::ZERO;
    let bus = open(config, ctx, stage).await?;
    let result = async {
        let source = bus
            .checked_source(ctx.skip_address_check)
            .await
            .map_err(|source| SwitchError::Service { stage, source })?;
        let options = crate::L4Options {
            source: crate::SourcePolicy::Known(source),
            tool_key: Some(key),
            authorize: crate::Authorize::Skip,
            ..crate::L4Options::default()
        };
        let mut l4 = bus
            .connect_l4(plan.target, &options)
            .await
            .map_err(|source| SwitchError::Service { stage, source })?;
        let result = async {
            if steps.iter().any(|s| s.step == Step::TunnellingUsers) {
                let table = wire::read_tunnelling_addresses(&mut l4).await?;
                let known = plan.notes.len();
                plan.resolve_tunnel_users(table.as_deref())?;
                for note in &plan.notes[known..] {
                    progress(note);
                }
            }
            run_steps(&mut l4, plan, steps, progress).await
        }
        .await;
        // After the master reset the device has dropped the connection and
        // is rebooting: a T_Disconnect would go unanswered.
        if !matches!(&result, Ok(r) if r.restart_seconds.is_some()) {
            let _ = l4.disconnect().await;
        }
        result.map_err(|source| SwitchError::Step { stage, source })
    }
    .await;
    bus.close().await;
    result
}

/// Switches KNXnet/IP Secure on or off as `plan` says, and verifies it.
///
/// `store` is the key store as loaded; the plan's generated credentials are
/// saved to it before the first write. After the restart the device is read
/// back on a fresh connection under the key it should now hold; when the
/// target is the gateway itself, that connection is a KNXnet/IP Secure session
/// with the key store's credentials (`on`) or a plain tunnel (`off`), and the
/// gateway's description must show tunnelling secure-only (`on`) or not
/// (`off`). `off` drops the tool key from the store once that verified.
///
/// # Errors
///
/// The first failure, naming the stage: the device holds everything before
/// it (see the module docs for the recovery).
pub async fn run_switch(
    ctx: &SwitchContext<'_>,
    plan: &mut SwitchPlan,
    store: &KeyStore,
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<SwitchOutcome, SwitchError> {
    let gateway = probe_gateway(&ctx.config).await;
    let target_is_gateway = gateway.and_then(|(ia, _)| ia) == Some(plan.target);
    let store_saved_before = plan
        .save_store(ctx.dir, ctx.keystore_password)
        .map_err(|source| SwitchError::Store {
            stage: "saving the generated credentials to the key store before the first write",
            source,
        })?;

    let first_steps = plan.first_connection().to_vec();
    let opening_key = plan.opening_key();
    let first = connection(
        ctx,
        ctx.config.clone(),
        plan,
        &first_steps,
        opening_key,
        "the switch",
        progress,
    )
    .await?;
    tokio::time::sleep(restart_wait(first.restart_seconds)).await;

    // After the restart: through the target itself the tunnel is plain after
    // `off` and secure after `on`.
    let switch = plan.switch;
    let after_config = || -> Result<bussard_transport::ConnectionConfig, SwitchError> {
        let mut config = ctx.config.clone();
        if target_is_gateway {
            config.secure = match switch {
                Switch::On => {
                    crate::secure::tunnel_config(crate::secure::TunnelCredentialSource {
                        keyring: Some(&KeyStore::path(ctx.dir)),
                        user: None,
                        password_env: None,
                    })?
                }
                Switch::Off => None,
            };
        }
        Ok(config)
    };

    let second_steps = plan.second_connection().to_vec();
    let second = if second_steps.is_empty() {
        None
    } else {
        let fdsk = plan.fdsk();
        let report = connection(
            ctx,
            after_config()?,
            plan,
            &second_steps,
            fdsk,
            "the factory-key pass after the restart",
            progress,
        )
        .await?;
        tokio::time::sleep(restart_wait(report.restart_seconds)).await;
        Some(report)
    };

    let config = after_config()?;
    let gateway_secure_only = if target_is_gateway {
        probe_gateway(&config).await.map(|(_, secure)| secure)
    } else {
        None
    };
    let key = match plan.switch {
        Switch::On => plan.tool_key(),
        Switch::Off => plan.fdsk(),
    };
    let stage = "the read-back after the restart";
    let bus = open(config, ctx, stage).await?;
    let verification = async {
        let source = bus
            .checked_source(ctx.skip_address_check)
            .await
            .map_err(|source| SwitchError::Service { stage, source })?;
        let options = crate::L4Options {
            source: crate::SourcePolicy::Known(source),
            tool_key: Some(key),
            authorize: crate::Authorize::Skip,
            ..crate::L4Options::default()
        };
        bus.with_l4(plan.target, &options, async |l4| {
            verify(l4, plan).await.map_err(BodyError::Step)
        })
        .await
        .map_err(|err| err.at(stage))
    }
    .await;
    bus.close().await;
    let verification = verification?;

    let mut outcome = SwitchOutcome {
        store_saved_before,
        first,
        second,
        gateway_secure_only,
        verification,
        store_saved_after: false,
    };
    if plan.switch == Switch::Off && outcome.verified(Switch::Off) {
        store_after_off(store, plan.target)
            .save(ctx.dir, ctx.keystore_password)
            .map_err(|source| SwitchError::Store {
                stage: "dropping the tool key from the key store after the verified switch",
                source,
            })?;
        outcome.store_saved_after = true;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_project::keystore::StoreDevice;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    /// A store with synthetic credentials for 1.1.200 and two tunnel users.
    fn store(with_tool_key: bool) -> Result<KeyStore, Box<dyn std::error::Error>> {
        let target = ia("1.1.200")?;
        let mut store = KeyStore::new("Synthetic");
        store.devices.insert(
            target,
            StoreDevice {
                tool_key: with_tool_key.then(|| Key16::new([0x42; 16])),
                fdsk: Some(Key16::new([0x24; 16])),
                management_password: Some(Password::new("synthetic-mgmt")),
                authentication: Some(Password::new("synthetic-auth")),
                ..StoreDevice::default()
            },
        );
        for (n, addr) in ["1.1.22", "1.1.23"].iter().enumerate() {
            store.interfaces.push(StoreInterface {
                interface_type: "Tunneling".into(),
                ia: ia(addr)?,
                host: Some(target),
                user_id: u8::try_from(n + 2)?,
                password: Some(Password::new(format!("synthetic-user-{}", n + 2))),
                authentication: Some(Password::new("synthetic-auth")),
                gas: Vec::new(),
            });
        }
        Ok(store)
    }

    #[test]
    fn test_plan_on_follows_the_ets_order() -> TestResult {
        let plan = plan_on(
            &store(true)?,
            ia("1.1.200")?,
            &[ia("1.1.22")?, ia("1.1.23")?],
        )?;
        let wire: Vec<(Option<(u16, u16)>, Phase)> = plan
            .steps
            .iter()
            .map(|s| (step_property(&s.step), s.phase))
            .collect();
        assert_eq!(
            wire,
            vec![
                (Some((17, 51)), Phase::Fdsk),
                (Some((17, 56)), Phase::Fdsk),
                (Some((17, 59)), Phase::Tool),
                (Some((11, 94)), Phase::Tool),
                (Some((11, 92)), Phase::Tool),
                (Some((11, 93)), Phase::Tool),
                (Some((11, 94)), Phase::Tool),
                (Some((11, 97)), Phase::Tool),
                (Some((11, 94)), Phase::Tool),
                (None, Phase::Tool),
            ]
        );
        assert_eq!(plan.tunnel_users, vec![(2, 1), (3, 2)]);
        assert!(plan.generated.is_empty());
        assert!(!plan.changes_store());
        Ok(())
    }

    #[test]
    fn test_resolve_tunnel_users_maps_through_pid_79() -> TestResult {
        let tunnels = [ia("1.1.22")?, ia("1.1.23")?];
        // PID 79 [0, 1, 2]: the own address first, so user 2 (PID 53 entry
        // 1) is table entry 2 and user 3 entry 3 (issue #520).
        let mut plan = plan_on(&store(true)?, ia("1.1.200")?, &tunnels)?;
        assert_eq!(plan.tunnel_users, vec![(2, 1), (3, 2)], "identity plan");
        plan.resolve_tunnel_users(Some(&[0, 1, 2]))?;
        assert_eq!(plan.tunnel_users, vec![(2, 2), (3, 3)]);
        assert!(plan.lines().iter().any(|l| l.contains("2->2 3->3")));
        assert_eq!(plan.notes.len(), 1, "{:?}", plan.notes);

        // The identity table changes nothing and notes nothing.
        let mut plan = plan_on(&store(true)?, ia("1.1.200")?, &tunnels)?;
        plan.resolve_tunnel_users(Some(&[1, 2]))?;
        assert_eq!(plan.tunnel_users, vec![(2, 1), (3, 2)]);
        assert!(plan.notes.is_empty());

        // No PID 79: the identity mapping, with a note.
        let mut plan = plan_on(&store(true)?, ia("1.1.200")?, &tunnels)?;
        plan.resolve_tunnel_users(None)?;
        assert_eq!(plan.tunnel_users, vec![(2, 1), (3, 2)]);
        assert!(plan.notes[0].contains("does not serve"), "{:?}", plan.notes);
        Ok(())
    }

    #[test]
    fn test_resolve_tunnel_users_refuses_an_address_outside_pid_79() -> TestResult {
        let mut plan = plan_on(
            &store(true)?,
            ia("1.1.200")?,
            &[ia("1.1.22")?, ia("1.1.23")?],
        )?;
        match plan.resolve_tunnel_users(Some(&[0, 2])) {
            Err(IpSecureError::NotATunnellingAddress { address, slot, .. }) => {
                assert_eq!(address, ia("1.1.22")?);
                assert_eq!(slot, 1);
            }
            other => return Err(format!("expected a refusal, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn test_plan_on_records_hash_key_material_only() -> TestResult {
        let plan = plan_on(
            &store(true)?,
            ia("1.1.200")?,
            &[ia("1.1.22")?, ia("1.1.23")?],
        )?;
        let records: Vec<PlanRecord> = plan
            .records()
            .into_iter()
            .flat_map(|s| s.properties)
            .collect();
        let tool = records
            .iter()
            .find(|r| r.pid == 56)
            .ok_or("no tool key record")?;
        assert_eq!(tool.data, None);
        assert_eq!(
            tool.sha256.as_deref(),
            Some(hex(&Sha256::digest([0x42u8; 16])).as_str())
        );
        let users = records
            .iter()
            .find(|r| r.pid == 97 && r.start_element == Some(1))
            .ok_or("no PID 97 record")?;
        assert_eq!(users.data.as_deref(), Some("02010302"));
        let hashes = records
            .iter()
            .find(|r| r.pid == 93 && r.start_element == Some(1))
            .ok_or("no PID 93 record")?;
        assert_eq!(hashes.length, 3 * 16);
        let mut expected = Vec::new();
        for pw in ["synthetic-mgmt", "synthetic-user-2", "synthetic-user-3"] {
            expected.extend_from_slice(Password::new(pw).derive(salt::USER_PASSWORD).bytes());
        }
        assert_eq!(
            hashes.sha256.as_deref(),
            Some(hex(&Sha256::digest(&expected)).as_str())
        );
        let rendered = format!("{plan:?} {}", plan.lines().join("\n"));
        assert!(!rendered.contains("synthetic-"), "{rendered}");
        assert!(!rendered.contains("4242"), "{rendered}");
        Ok(())
    }

    #[test]
    fn test_plan_on_generates_missing_credentials_into_the_store() -> TestResult {
        let mut store = store(false)?;
        store.interfaces.clear();
        let target = ia("1.1.200")?;
        let plan = plan_on(&store, target, &[ia("1.1.22")?, ia("1.1.23")?])?;
        assert!(plan.changes_store());
        assert_eq!(
            plan.generated,
            vec![
                "tool key".to_string(),
                "password of tunnelling user 2 (1.1.22)".to_string(),
                "password of tunnelling user 3 (1.1.23)".to_string(),
            ]
        );
        let updated = plan.store_update.as_ref().ok_or("no store update")?;
        assert!(updated.devices[&target].tool_key.is_some());
        assert_eq!(
            updated
                .interfaces
                .iter()
                .map(|i| (i.ia.to_string(), i.user_id, i.host))
                .collect::<Vec<_>>(),
            vec![
                ("1.1.22".to_string(), 2, Some(target)),
                ("1.1.23".to_string(), 3, Some(target)),
            ]
        );
        Ok(())
    }

    #[test]
    fn test_plan_on_refuses_without_fdsk_or_tunnels() -> TestResult {
        let mut store = store(true)?;
        let target = ia("1.1.200")?;
        assert!(matches!(
            plan_on(&store, target, &[]),
            Err(IpSecureError::NoTunnels(_))
        ));
        if let Some(dev) = store.devices.get_mut(&target) {
            dev.fdsk = None;
        }
        assert!(matches!(
            plan_on(&store, target, &[ia("1.1.22")?]),
            Err(IpSecureError::NoFdsk(_))
        ));
        Ok(())
    }

    #[test]
    fn test_plan_on_refuses_a_gap_in_the_user_ids() -> TestResult {
        let mut store = store(true)?;
        if let Some(iface) = store.interfaces.get_mut(1) {
            iface.user_id = 5;
        }
        let err = plan_on(&store, ia("1.1.200")?, &[ia("1.1.22")?, ia("1.1.23")?])
            .err()
            .ok_or("planned")?;
        assert!(
            err.to_string()
                .contains("no tunnelling address has user id 3"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn test_plan_off_runs_two_connections() -> TestResult {
        let plan = plan_off(&store(true)?, ia("1.1.200")?)?;
        assert_eq!(plan.first_connection().len(), 6);
        assert_eq!(plan.second_connection().len(), 4);
        assert!(
            plan.first_connection()[..5]
                .iter()
                .all(|s| s.phase == Phase::Tool)
        );
        assert!(
            plan.second_connection()
                .iter()
                .all(|s| s.phase == Phase::Fdsk)
        );
        assert!(matches!(
            plan_off(&store(false)?, ia("1.1.200")?),
            Err(IpSecureError::NoToolKey(_))
        ));
        let after = store_after_off(&store(true)?, ia("1.1.200")?);
        let dev = &after.devices[&ia("1.1.200")?];
        assert!(dev.tool_key.is_none() && dev.fdsk.is_some());
        Ok(())
    }
}
