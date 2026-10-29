//! The KNXnet/IP Secure properties of a simulated KNX IP interface (bussard
//! issue #398): `PID_BACKBONE_KEY` (91), `PID_DEVICE_AUTHENTICATION_CODE`
//! (92), `PID_PASSWORD_HASHES` (93), the function property
//! `PID_SECURED_SERVICE_FAMILIES` (94) and `PID_TUNNELLING_USERS` (97) of the
//! KNXnet/IP parameter object (type 11), reached by the extended property
//! services as ETS reaches them.
//!
//! Ids from the KNX master data (`knx_master.xml`, `PID-11-91` to
//! `PID-11-97`); layouts from the ETS activation capture of 1.1.200
//! (2026-10-26): a function command `00 00 family on` answered with return
//! code 0 and one octet, PIDs 93 and 97 arrays whose element 0 is the count
//! (16-octet hashes; `user id, address index` pairs).
//!
//! What the properties say takes effect at the next master reset
//! ([`IpSecureObject::apply`]): the device then publishes an
//! [`IpSecureState`] and bumps its epoch, and the simulator's KNXnet/IP
//! server (when the config names this device as the interface it serves,
//! `gateway.interface_device`) switches between plain tunnelling and secure
//! sessions with these credentials. The keys are synthetic in every test and
//! never logged.

use std::collections::BTreeMap;

/// `PID_BACKBONE_KEY`.
pub const PID_BACKBONE_KEY: u16 = 91;
/// `PID_DEVICE_AUTHENTICATION_CODE`.
pub const PID_DEVICE_AUTHENTICATION_CODE: u16 = 92;
/// `PID_PASSWORD_HASHES`.
pub const PID_PASSWORD_HASHES: u16 = 93;
/// `PID_SECURED_SERVICE_FAMILIES` (function property).
pub const PID_SECURED_SERVICE_FAMILIES: u16 = 94;
/// `PID_TUNNELLING_USERS`.
pub const PID_TUNNELLING_USERS: u16 = 97;

/// The KNXnet/IP service family id of tunnelling.
pub const FAMILY_TUNNELLING: u8 = 0x04;

/// Whether `pid` is one of the KNXnet/IP Secure properties this module serves.
pub fn is_ip_secure_pid(pid: u16) -> bool {
    matches!(
        pid,
        PID_BACKBONE_KEY
            | PID_DEVICE_AUTHENTICATION_CODE
            | PID_PASSWORD_HASHES
            | PID_SECURED_SERVICE_FAMILIES
            | PID_TUNNELLING_USERS
    )
}

/// The KNXnet/IP Secure credentials in effect after a master reset.
#[derive(Clone, PartialEq, Eq)]
pub struct IpSecureState {
    /// The device authentication code's key.
    pub device_key: [u8; 16],
    /// `(user id, password key, tunnelling address)` per tunnelling user.
    pub users: Vec<(u8, [u8; 16], u16)>,
    /// The secured service families.
    pub families: Vec<u8>,
}

impl std::fmt::Debug for IpSecureState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpSecureState")
            .field("users", &self.users.len())
            .field("families", &self.families)
            .finish_non_exhaustive()
    }
}

/// The written values of the KNXnet/IP Secure properties.
#[derive(Clone, Default)]
pub struct IpSecureObject {
    backbone_key: Option<[u8; 16]>,
    device_key: Option<[u8; 16]>,
    /// Element n (1-based) at index n-1.
    hashes: Vec<[u8; 16]>,
    users: Vec<(u8, u8)>,
    families: BTreeMap<u8, bool>,
    /// What the last master reset put in effect; `None` while plain.
    applied: Option<IpSecureState>,
    /// Bumped by every master reset, so the server sees a change.
    epoch: u64,
}

impl std::fmt::Debug for IpSecureObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpSecureObject")
            .field("backbone_key", &self.backbone_key.is_some())
            .field("device_key", &self.device_key.is_some())
            .field("hashes", &self.hashes.len())
            .field("users", &self.users)
            .field("families", &self.families)
            .field("applied", &self.applied)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// The 5-octet extended header: object type, instance, PID.
fn header(data: &[u8]) -> Option<(u16, u32, u16)> {
    let h = data.get(..5)?;
    let packed = (u32::from(h[2]) << 16) | (u32::from(h[3]) << 8) | u32::from(h[4]);
    Some((
        u16::from_be_bytes([h[0], h[1]]),
        packed >> 12,
        (packed & 0x0FFF) as u16,
    ))
}

impl IpSecureObject {
    /// A plain interface (factory state): nothing written, nothing secured.
    pub fn new() -> Self {
        Self::default()
    }

    /// What the last master reset put in effect.
    pub fn applied(&self) -> Option<&IpSecureState> {
        self.applied.as_ref()
    }

    /// The master-reset counter.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The tunnelling users as written (for tests).
    pub fn users(&self) -> &[(u8, u8)] {
        &self.users
    }

    /// Whether `family` is set to secured (written, not yet applied).
    pub fn family_secured(&self, family: u8) -> bool {
        self.families.get(&family).copied().unwrap_or(false)
    }

    /// An `A_PropertyExtValue_WriteCon` of a KNXnet/IP Secure property: the
    /// confirmation payload (header, count, start, return code), or `None`
    /// for another property.
    pub fn write(&mut self, request: &[u8]) -> Option<Vec<u8>> {
        let (object_type, instance, pid) = header(request)?;
        if object_type != 11 || !is_ip_secure_pid(pid) || pid == PID_SECURED_SERVICE_FAMILIES {
            return None;
        }
        let h = request.get(..8)?;
        let count = usize::from(h[5]);
        let start = usize::from(u16::from_be_bytes([h[6], h[7]]));
        let data = request.get(8..).unwrap_or_default();
        let ok = instance == 1 && self.write_value(pid, count, start, data);
        let mut out = h.to_vec();
        out.push(if ok { 0x00 } else { 0x01 });
        Some(out)
    }

    fn write_value(&mut self, pid: u16, count: usize, start: usize, data: &[u8]) -> bool {
        let key16 = |b: &[u8]| -> Option<[u8; 16]> { b.try_into().ok() };
        match (pid, start) {
            (PID_BACKBONE_KEY, 1) if count == 1 => {
                key16(data).map(|k| self.backbone_key = Some(k)).is_some()
            }
            (PID_DEVICE_AUTHENTICATION_CODE, 1) if count == 1 => {
                key16(data).map(|k| self.device_key = Some(k)).is_some()
            }
            (PID_PASSWORD_HASHES | PID_TUNNELLING_USERS, 0) if count == 1 && data.len() == 2 => {
                let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
                if n > 15 {
                    return false;
                }
                if pid == PID_PASSWORD_HASHES {
                    self.hashes.resize(n, [0; 16]);
                } else {
                    self.users.resize(n, (0, 0));
                }
                true
            }
            (PID_PASSWORD_HASHES, s) if s >= 1 && data.len() == count * 16 => {
                let last = s - 1 + count;
                if last > self.hashes.len() {
                    return false;
                }
                for (i, chunk) in data.chunks(16).enumerate() {
                    if let Some(k) = key16(chunk) {
                        self.hashes[s - 1 + i] = k;
                    }
                }
                true
            }
            (PID_TUNNELLING_USERS, s) if s >= 1 && data.len() == count * 2 => {
                let last = s - 1 + count;
                if last > self.users.len() {
                    return false;
                }
                for (i, pair) in data.chunks(2).enumerate() {
                    self.users[s - 1 + i] = (pair[0], pair[1]);
                }
                true
            }
            _ => false,
        }
    }

    /// An `A_PropertyExtValue_Read` of `PID_TUNNELLING_USERS` (readable;
    /// the key PIDs are write-only and answer zero elements).
    pub fn read(&self, request: &[u8]) -> Option<Vec<u8>> {
        let (object_type, instance, pid) = header(request)?;
        if object_type != 11 || !is_ip_secure_pid(pid) || pid == PID_SECURED_SERVICE_FAMILIES {
            return None;
        }
        let h = request.get(..8)?;
        let count = usize::from(h[5]);
        let start = usize::from(u16::from_be_bytes([h[6], h[7]]));
        let answer: Option<(u8, Vec<u8>)> = match (instance, pid) {
            (1, PID_TUNNELLING_USERS) if start == 0 => {
                let n = u16::try_from(self.users.len()).unwrap_or(0);
                Some((1, n.to_be_bytes().to_vec()))
            }
            (1, PID_TUNNELLING_USERS) if count > 0 && start - 1 + count <= self.users.len() => {
                let elems = &self.users[start - 1..start - 1 + count];
                Some((
                    u8::try_from(count).unwrap_or(0),
                    elems.iter().flat_map(|&(u, i)| [u, i]).collect(),
                ))
            }
            _ => None,
        };
        let (n, bytes) = answer.unwrap_or((0, Vec::new()));
        let mut out = h[..5].to_vec();
        out.push(n);
        out.extend_from_slice(&h[6..8]);
        out.extend_from_slice(&bytes);
        Some(out)
    }

    /// An `A_FunctionPropertyExt_Command` (`set`) or `_State_Read` of
    /// `PID_SECURED_SERVICE_FAMILIES`: the state response payload (header,
    /// return code, one octet), or `None` for another property.
    pub fn function(&mut self, request: &[u8], command: bool) -> Option<Vec<u8>> {
        let (object_type, instance, pid) = header(request)?;
        if object_type != 11 || pid != PID_SECURED_SERVICE_FAMILIES {
            return None;
        }
        let body = request.get(5..).unwrap_or_default();
        let (rc, octet) = match (instance, command, body) {
            (1, true, [_, 0x00, family, on]) if *on <= 1 => {
                self.families.insert(*family, *on == 1);
                (0x00, 0x00)
            }
            (1, false, [_, 0x00, family]) => (0x00, u8::from(self.family_secured(*family))),
            _ => (0x01, 0x00),
        };
        let mut out = request[..5].to_vec();
        out.push(rc);
        out.push(octet);
        Some(out)
    }

    /// The master reset: what the properties say takes effect. Tunnelling
    /// secured with a device authentication code and at least one user with a
    /// written hash makes the interface secure; anything else plain.
    ///
    /// A `PID_TUNNELLING_USERS` entry names its address through two tables
    /// (KNX IP Secure 3/8/9 §2.3.1.8.3; Device Management 3/8/3 §2.5.29;
    /// bussard issue #520): its index points into `table`
    /// (`PID_TUNNELLING_ADDRESSES`, 1-based), whose value is 0 for the
    /// interface's `own` address or the 1-based index into `tunnels`
    /// (`PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`, raw, slot order). Without a
    /// table the index points into `tunnels` directly.
    pub fn apply(&mut self, own: u16, tunnels: &[u16], table: Option<&[u8]>) {
        self.epoch += 1;
        let resolve = |index: u8| -> Option<u16> {
            let id = match table {
                Some(table) => *table.get(usize::from(index).checked_sub(1)?)?,
                None => index,
            };
            match id {
                0 => Some(own),
                n => tunnels.get(usize::from(n) - 1).copied(),
            }
        };
        let users: Vec<(u8, [u8; 16], u16)> = self
            .users
            .iter()
            .filter_map(|&(user, index)| {
                let key = *self.hashes.get(usize::from(user).checked_sub(1)?)?;
                Some((user, key, resolve(index)?))
            })
            .collect();
        let families: Vec<u8> = self
            .families
            .iter()
            .filter(|(_, on)| **on)
            .map(|(f, _)| *f)
            .collect();
        self.applied = match self.device_key {
            Some(device_key) if families.contains(&FAMILY_TUNNELLING) && !users.is_empty() => {
                Some(IpSecureState {
                    device_key,
                    users,
                    families,
                })
            }
            _ => None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    #[test]
    fn test_activation_sequence_puts_the_credentials_in_effect() {
        let mut obj = IpSecureObject::new();
        let auth = [0x11u8; 16];
        let mut req = hex("000b 00105c 01 0001");
        req.extend_from_slice(&auth);
        assert_eq!(obj.write(&req), Some(hex("000b 00105c 01 0001 00")));
        assert_eq!(
            obj.write(&hex("000b 00105d 01 0000 0002")),
            Some(hex("000b 00105d 01 0000 00"))
        );
        let mut hashes = hex("000b 00105d 02 0001");
        hashes.extend_from_slice(&[0x21; 16]);
        hashes.extend_from_slice(&[0x22; 16]);
        assert_eq!(obj.write(&hashes), Some(hex("000b 00105d 02 0001 00")));
        assert!(obj.write(&hex("000b 001061 01 0000 0001")).is_some());
        assert!(obj.write(&hex("000b 001061 01 0001 0201")).is_some());
        assert_eq!(
            obj.function(&hex("000b 00105e 00 00 04 01"), true),
            Some(hex("000b 00105e 00 00"))
        );
        assert_eq!(
            obj.read(&hex("000b 001061 01 0001")),
            Some(hex("000b 001061 01 0001 0201"))
        );
        assert!(
            obj.applied().is_none(),
            "nothing in effect before the reset"
        );
        obj.apply(0x11C8, &[0x1116], None);
        let state = obj.applied().cloned().unwrap_or(IpSecureState {
            device_key: [0; 16],
            users: Vec::new(),
            families: Vec::new(),
        });
        assert_eq!(state.device_key, auth);
        assert_eq!(state.users, vec![(2, [0x22; 16], 0x1116)]);
        assert_eq!(obj.epoch(), 1);
        // Tunnelling not secured: plain after the next reset.
        assert!(
            obj.function(&hex("000b 00105e 00 00 04 00"), true)
                .is_some()
        );
        obj.apply(0x11C8, &[0x1116], None);
        assert!(obj.applied().is_none());
        assert_eq!(obj.epoch(), 2);
    }

    #[test]
    fn test_apply_resolves_users_through_the_tunnelling_addresses() {
        // PID 79 [0, 2, 3]: the own address, then PID 53 entries 2 and 3.
        let mut obj = IpSecureObject::new();
        let mut auth = hex("000b 00105c 01 0001");
        auth.extend_from_slice(&[0x11; 16]);
        obj.write(&auth);
        obj.write(&hex("000b 00105d 01 0000 0003"));
        let mut hashes = hex("000b 00105d 03 0001");
        hashes.extend_from_slice(&[0x21; 48]);
        obj.write(&hashes);
        obj.write(&hex("000b 001061 01 0000 0002"));
        // User 2 on table entry 1 (own address), user 3 on entry 3 (1.1.24).
        obj.write(&hex("000b 001061 02 0001 0201 0303"));
        obj.function(&hex("000b 00105e 00 00 04 01"), true);
        obj.apply(0x11C8, &[0x1116, 0x1117, 0x1118], Some(&[0, 2, 3]));
        let users: Vec<(u8, u16)> = obj
            .applied()
            .map(|s| s.users.iter().map(|&(u, _, ia)| (u, ia)).collect())
            .unwrap_or_default();
        assert_eq!(users, vec![(2, 0x11C8), (3, 0x1118)]);
    }

    #[test]
    fn test_debug_shows_no_key() {
        let mut obj = IpSecureObject::new();
        let mut req = hex("000b 00105c 01 0001");
        req.extend_from_slice(&[0xAB; 16]);
        obj.write(&req);
        assert!(!format!("{obj:?}").contains("171"), "{obj:?}");
    }
}
