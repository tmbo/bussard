//! KNX Data Secure GROUP communication (issue #172): secured `A_SecureData`
//! telegrams to a group address, protected with the group key of that address.
//!
//! The keys come from the device's own security interface object: the group key
//! table (PID 53) names an address-table index (the 1-based TSAP) per key, and
//! the address table (obj1) the download wrote maps that index to a group
//! address. The group-object security flags (PID 61) mark which com-objects are
//! secured. So a device only speaks secured group traffic after a tool has
//! flashed it with a keyring, exactly as a real device.
//!
//! Behaviour of a security-activated device:
//!
//! - an inbound secured telegram to a group address whose key it holds is
//!   verified (MAC, per-source freshness), decrypted and dispatched through the
//!   ordinary [`Device::handle_group`]; any response is sealed with the same
//!   group key and the device's own send sequence;
//! - a plain telegram to a group address that one of its secured com-objects
//!   is linked to is ignored (a secured object never trusts plain traffic);
//! - a wrong MAC or a stale sequence drops the telegram;
//! - a secured telegram from a sender the security individual address table
//!   (PID 54) does not list is dropped, and one whose sequence does not exceed
//!   the sender's table entry too (issue #181: ETS lists every secured sender
//!   of a device there);
//! - a verified telegram whose security (auth+conf or auth only) does not
//!   match the group-object security flags of every object linked to the
//!   group address is ignored (KNX 3/5/1 §6.3.15.3 Table 108).
//!
//! The checks run in the order of KNX 3/3/7 §5.5.3.2 and §5.2.1.1: the key
//! of the group address (none: ignored), the tool-access flag (set on a
//! group telegram: an attack, counted as an access error), the sender table,
//! the sequence (PID 54 entry and the per-sender table), the MAC, the
//! reserved bits of the inner APDU (§5.2.1.4: dropped, not counted), then the
//! group-object flags.
//!
//! The failures land in the security failures log (PID 55, bussard issue
//! #533) as the standard counts them: a MAC that does not verify or a frame
//! too short is a cryptographic error, a stale sequence a SeqNr error (KNX
//! 3/3/7 §5.4), a flag mismatch an access error; an unlisted sender is
//! dropped without a count (§5.2.1.1). Each sets the security report, and
//! with the report control on the device broadcasts it as an
//! `A_NetworkParameter_InfoReport` (KNX 3/5/1 §6.3.11.4).
//!
//! Every outcome lands on the event log as a key-free, plaintext-free line
//! (`SECURE group recv ...`, `SECURE group send ...`, `REJECTED SECURE group
//! ...`, `IGNORED PLAIN group ...`) a script can grep for.

use crate::bus::event::Event;
use crate::bus::{decode_group, response_as_write};
use crate::secure::{A_SECURE_DATA_APCI, Key16, Scf, SecAlgorithm};
use crate::wire::{CemiLData, GroupAddress};

use super::security_object::FailureKind;
use super::{Device, LoadState, SecLoadState, group_comm};

/// `A_NetworkParameter_Response`, the APCI of an InfoReport (KNX 3/3/7
/// §3.2.8).
const A_NETWORK_PARAMETER_RESPONSE: u16 = 0x3DB;

/// The algorithm a device uses for group telegrams it originates (stimulus):
/// authentication + encryption, SCF `0x10`, what ETS configures by default.
const GROUP_SEND_ALGORITHM: SecAlgorithm = SecAlgorithm::AuthEnc;

/// A short `[auth]` / `[auth+enc]` tag for an SCF on the event log.
fn scf_tag(scf: Scf) -> &'static str {
    match scf.algorithm {
        SecAlgorithm::AuthOnly => "auth",
        SecAlgorithm::AuthEnc => "auth+enc",
    }
}

/// The 48-bit value of a 6-byte sequence field, for the event log.
fn seq_value(seq: &[u8; 6]) -> u64 {
    let mut buf = [0u8; 8];
    buf[2..].copy_from_slice(seq);
    u64::from_be_bytes(buf)
}

/// Whether a telegram carries the `A_SecureData` APCI.
fn is_secure_data(cemi: &CemiLData) -> bool {
    cemi.tpdu.len() >= 2
        && (((cemi.tpdu[0] as u16 & 0x03) << 8) | cemi.tpdu[1] as u16) == A_SECURE_DATA_APCI
}

/// The group service of a plain group APDU (for the event log).
fn inner_name(inner: &[u8]) -> String {
    crate::wire::apdu::Apdu::parse(inner)
        .map(|a| format!("{:?}", a.apci))
        .unwrap_or_else(|| "?".to_string())
}

impl Device {
    /// Handle a group telegram seen on the bus, plain or secured, and return the
    /// telegrams the device sends in reply.
    ///
    /// `listener` selects the mode: `false` for a telegram a device may answer
    /// (from the tool), `true` for a telegram another device put on the bus,
    /// which only updates listeners (a `_Response` counts as a `_Write`) and
    /// never draws a reply.
    pub fn handle_group_frame(&mut self, cemi: &CemiLData, listener: bool) -> Vec<CemiLData> {
        if is_secure_data(cemi) {
            return self.handle_secure_group(cemi, listener);
        }
        let Some((apci, ga, payload)) = decode_group(cemi) else {
            return Vec::new();
        };
        if let Some(object) = self.secured_object_on(ga) {
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: format!(
                    "IGNORED PLAIN group {apci:?} {} -> {ga}: group object {object} requires KNX Data Secure",
                    cemi.source
                ),
            });
            return Vec::new();
        }
        if listener {
            let _ = self.handle_group(response_as_write(apci), ga, &payload);
            return Vec::new();
        }
        self.handle_group(apci, ga, &payload)
    }

    /// The group key this device holds for `ga`: the PID 53 row naming the
    /// address-table index of `ga`. `None` unless the device is activated, its
    /// security object is `Loaded` and its address table is loaded.
    fn group_key_for(&self, ga: GroupAddress) -> Option<Key16> {
        self.secure.as_ref()?;
        let obj = self.security_object.as_ref()?;
        if obj.load_state() != SecLoadState::Loaded || self.sys7.is_some() {
            return None;
        }
        if self.load_state(1) != Some(LoadState::Loaded) {
            return None;
        }
        let addresses = group_comm::address_table(&self.memory, self.base_of(1)?);
        let tsap = addresses.iter().position(|a| *a == ga)? + 1;
        obj.group_key_for_address_index(u16::try_from(tsap).ok()?)
    }

    /// Whether com-object `object` carries a group-object security flag (PID 61
    /// element `object` non-zero) on an activated device.
    fn object_is_secured(&self, object: u16) -> bool {
        self.secure.is_some()
            && self
                .security_object
                .as_ref()
                .and_then(|o| o.go_flag(object))
                .is_some_and(|f| f != 0)
    }

    /// The first secured com-object linked to `ga`, if any: such a group address
    /// accepts only secured telegrams on this device.
    fn secured_object_on(&self, ga: GroupAddress) -> Option<u16> {
        let gc = self.group_comm.as_ref()?;
        gc.objects()
            .values()
            .filter(|o| o.gas.contains(&ga))
            .map(|o| o.asap)
            .find(|&asap| self.object_is_secured(asap))
    }

    /// Verify, decrypt and dispatch an inbound secured group telegram, sealing
    /// every response. A device that holds no key for the destination ignores
    /// the telegram silently (it is not a member of that secured group).
    fn handle_secure_group(&mut self, cemi: &CemiLData, listener: bool) -> Vec<CemiLData> {
        let ga = cemi.dest_group();
        let Some(key) = self.group_key_for(ga) else {
            return Vec::new();
        };
        let source = cemi.source;
        let asdu = &cemi.tpdu[2..];
        let mut wire_seq = [0u8; 6];
        if let Some(s) = asdu.get(1..7) {
            wire_seq.copy_from_slice(s);
        }
        // KNX 3/3/7 §5.5.3.2 step 1.1.1: a group telegram that claims tool
        // access is an attack, counted as an access or roles error (04h).
        if asdu.first().is_some_and(|scf| scf & 0x80 != 0) {
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: format!(
                    "REJECTED SECURE group recv {source} -> {ga}: tool access flag on a group \
                     telegram (access error)"
                ),
            });
            return self.security_failure(FailureKind::Access, source.raw(), wire_seq);
        }
        // §5.2.1.1: the sender table, then the sequence, then the MAC.
        let Some(listed_seq) = self
            .security_object
            .as_ref()
            .and_then(|o| o.ia_table_sequence(source.raw()))
        else {
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: format!(
                    "REJECTED SECURE group recv {source} -> {ga}: sender not in the security \
                     individual address table (PID 54)"
                ),
            });
            return Vec::new();
        };
        if seq_value(&wire_seq) <= listed_seq {
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: format!(
                    "REJECTED SECURE group recv {source} -> {ga}: sequence {} not above the PID 54 \
                     entry {listed_seq}",
                    seq_value(&wire_seq)
                ),
            });
            return self.security_failure(FailureKind::SeqNr, source.raw(), wire_seq);
        }
        let opened = match self.secure.as_mut() {
            Some(session) => session.unwrap_group_incoming(&key, cemi, asdu),
            None => return Vec::new(),
        };
        let unwrapped = match opened {
            Ok(u) => u,
            Err(err) => {
                self.emit(Event::SecureFrame {
                    device: self.address,
                    summary: format!("REJECTED SECURE group recv {source} -> {ga}: {err}"),
                });
                let kind = match err {
                    crate::secure::SecureError::StaleSequence { .. } => Some(FailureKind::SeqNr),
                    crate::secure::SecureError::BadMac
                    | crate::secure::SecureError::TooShort { .. } => {
                        Some(FailureKind::Cryptographic)
                    }
                    _ => None,
                };
                return match kind {
                    Some(kind) => self.security_failure(kind, source.raw(), wire_seq),
                    None => Vec::new(),
                };
            }
        };
        // Table 108: the telegram's A/C must match the flags of the objects
        // linked to the group address exactly.
        let used = match unwrapped.scf.algorithm {
            SecAlgorithm::AuthOnly => 0x01,
            SecAlgorithm::AuthEnc => 0x03,
        };
        if let Some(object) = self.flag_mismatch(ga, used) {
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: format!(
                    "REJECTED SECURE group recv {source} -> {ga}: group object {object} security \
                     flags do not match scf=0x{:02x}[{}] (access error)",
                    unwrapped.scf.to_byte(),
                    scf_tag(unwrapped.scf),
                ),
            });
            return self.security_failure(FailureKind::Access, source.raw(), unwrapped.seq);
        }
        let inner_carrier = CemiLData {
            tpdu: unwrapped.inner_tpdu.clone(),
            ..cemi.clone()
        };
        let Some((apci, _, payload)) = decode_group(&inner_carrier) else {
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: format!(
                    "REJECTED SECURE group recv {source} -> {ga}: inner APDU {} is not a group service",
                    inner_name(&unwrapped.inner_tpdu)
                ),
            });
            return Vec::new();
        };
        self.emit(Event::SecureFrame {
            device: self.address,
            summary: format!(
                "SECURE group recv {source} -> {ga} scf=0x{:02x}[{}] seq={} inner={apci:?} ok",
                unwrapped.scf.to_byte(),
                scf_tag(unwrapped.scf),
                seq_value(&unwrapped.seq),
            ),
        });
        if listener {
            let _ = self.handle_group(response_as_write(apci), ga, &payload);
            return Vec::new();
        }
        let responses = self.handle_group(apci, ga, &payload);
        // A response mirrors the request's algorithm, as for tool access.
        responses
            .into_iter()
            .filter_map(|r| self.seal_group_telegram(r, unwrapped.scf.algorithm))
            .collect()
    }

    /// The first object linked to `ga` whose group-object security flags are
    /// not `used` (the telegram's A/C bits), if any.
    fn flag_mismatch(&self, ga: GroupAddress, used: u8) -> Option<u16> {
        let gc = self.group_comm.as_ref()?;
        let obj = self.security_object.as_ref()?;
        gc.objects()
            .values()
            .filter(|o| o.gas.contains(&ga))
            .map(|o| o.asap)
            .find(|&asap| obj.go_flag(asap).unwrap_or(0) & 0x03 != used)
    }

    /// Records a security failure in the security object and returns the
    /// broadcast security report when the report control asks for one.
    fn security_failure(&mut self, kind: FailureKind, sender: u16, seq: [u8; 6]) -> Vec<CemiLData> {
        let Some(obj) = self.security_object.as_mut() else {
            return Vec::new();
        };
        if !obj.record_failure(kind, sender, seq) {
            return Vec::new();
        }
        let report = obj.security_report();
        self.emit(Event::SecureFrame {
            device: self.address,
            summary: format!("SECURE report broadcast 0x{report:02x} (PID 57)"),
        });
        let apci = A_NETWORK_PARAMETER_RESPONSE;
        vec![CemiLData {
            message_code: crate::wire::cemi::MessageCode::LDataInd,
            // Urgent priority, broadcast (group destination 0/0/0), hop count 6.
            ctrl1: 0xb8,
            ctrl2: 0xe0,
            source: self.address,
            dest: 0x0000,
            tpdu: vec![
                (apci >> 8) as u8 & 0x03,
                (apci & 0xFF) as u8,
                0x00,
                0x11,
                57,
                0x00,
                report,
            ],
        }]
    }

    /// Seal a plain outgoing group telegram into `A_SecureData` with the group
    /// key of its destination and the device's next send sequence. `None` (and
    /// a `REJECTED` log line) when the device holds no key for it.
    fn seal_group_telegram(
        &mut self,
        plain: CemiLData,
        algorithm: SecAlgorithm,
    ) -> Option<CemiLData> {
        let ga = plain.dest_group();
        let Some(key) = self.group_key_for(ga) else {
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: format!(
                    "REJECTED SECURE group send {} -> {ga}: no group key for the address",
                    plain.source
                ),
            });
            return None;
        };
        // The inner APDU is the plain group APDU with the TPCI bits cleared.
        let mut inner = plain.tpdu.clone();
        if let Some(first) = inner.first_mut() {
            *first &= 0x03;
        }
        let apci10 = A_SECURE_DATA_APCI;
        let carrier_tpdu = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8];
        let carrier = CemiLData {
            tpdu: carrier_tpdu.clone(),
            ..plain.clone()
        };
        let (asdu, seq) = self
            .secure
            .as_mut()?
            .wrap_group_outgoing(&key, &carrier, algorithm, &inner);
        let scf = crate::secure::group_scf(algorithm);
        self.emit(Event::SecureFrame {
            device: self.address,
            summary: format!(
                "SECURE group send {} -> {ga} scf=0x{:02x}[{}] seq={} inner={}",
                plain.source,
                scf.to_byte(),
                scf_tag(scf),
                seq_value(&seq),
                inner_name(&inner),
            ),
        });
        let mut tpdu = carrier_tpdu;
        tpdu.extend_from_slice(&asdu);
        Some(CemiLData { tpdu, ..plain })
    }

    /// Seal a device-originated telegram for com-object `object` when that
    /// object is secured; pass it through unchanged otherwise.
    pub(super) fn secure_if_flagged(&mut self, object: u16, plain: CemiLData) -> Option<CemiLData> {
        if self.object_is_secured(object) {
            self.seal_group_telegram(plain, GROUP_SEND_ALGORITHM)
        } else {
            Some(plain)
        }
    }
}
