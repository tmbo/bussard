//! A strict, independent KNX System-B device.
//!
//! The device holds its memory map, interface objects and per-object load-state
//! machines, and implements the device side of the management protocol exactly
//! and strictly. It is driven one management APDU at a time via
//! [`Device::handle_apdu`], which returns the response APDU(s) to send back and
//! records observations on the event stream.

mod apci;
mod build;
mod data_secure;
mod group_comm;
mod group_dispatch;
mod interface_object;
pub mod ip_secure;
pub mod knxnet_object;
mod load_state;
mod lsm;
mod mcb;
mod memory;
mod memory_access;
pub mod profile;
mod properties;
mod restart;
mod secure_group;
pub mod security_object;
mod sys7_group_comm;
pub mod sys7_lsm;
#[cfg(test)]
mod test_support;
mod transport;

pub use group_comm::{ComObject, GroupComm, flag};
pub use interface_object::{
    InterfaceObject, PDT_GENERIC_01, PID_LOAD_STATE_CONTROL, PID_MCB_TABLE, PID_OBJECT_TYPE,
    PID_PROGMODE, PID_PROGRAM_VERSION, PID_TABLE, PID_TABLE_REFERENCE, Property,
    PropertyDescription, iot,
};
pub use lsm::{
    LoadEvent, LoadState, LoadStateMachine, Sys7LoadStateMachine, Sys7Step, Sys7TransitionError,
};
pub use mcb::{MCB_ENTRY_LEN, crc16_aug_ccitt, mcb_entry};
pub use memory::{Memory, MemoryError, Segment};
pub use profile::{
    LsmAccess, MaskFamily, MemoryMappedLsm, Profile, Sys7MemoryMap, Sys7Profile, mask_family,
    parse_mask,
};
pub use security_object::{SecLoadState, SecurityLimits, SecurityObject};
pub use sys7_group_comm::Sys7GroupComm;
pub use sys7_lsm::{Sys7Event, Sys7EventError};
pub use transport::{ACKNOWLEDGE_TIMEOUT, CONNECTION_TIMEOUT, MAX_REPETITIONS};

/// The KNX free-access authorize key: an unkeyed device grants full access to
/// any tool presenting this key (spec section 6).
pub const FREE_ACCESS_KEY: u32 = 0xFFFF_FFFF;

/// The conservative System 7 memory chunk: max 12 data octets per
/// `A_Memory_Write`/`_Read` on a standard frame (spec section 6). A memory op to
/// a System 7 device carrying more than this is refused as a real device refuses.
pub const SYS7_MAX_MEMORY_CHUNK: usize = 12;

/// The master-reset erase code for a factory reset that keeps the individual
/// address (KNX `A_Restart` erase code 7).
pub const ERASE_CODE_FACTORY_RESET_KEEP_IA: u8 = 0x07;

/// The process time (seconds) a device reports in its `A_Restart_Response` to a
/// factory reset, unless set with [`Device::set_restart_process_time`]. The real
/// Jung device in the issue #117 capture reports 8 s; the simulator answers
/// faster so a simulated flash does not idle.
pub const DEFAULT_RESTART_PROCESS_TIME_S: u16 = 1;

use std::collections::BTreeMap;

use crate::bus::event::{Event, EventSink};
use crate::prod::{LoadableObject, ProductData};
use crate::wire::apdu::{Apci, Apdu};
use crate::wire::{CemiLData, IndividualAddress, MessageCode, Tpci};

/// How a device reacted to one inbound telegram.
#[derive(Debug, Default)]
pub struct DeviceReaction {
    /// Response telegrams to send back toward the tool (already framed as cEMI
    /// `L_Data.ind`).
    pub responses: Vec<CemiLData>,
    /// True if the device just performed a master reset and is "rebooting".
    pub did_master_reset: bool,
}

/// The reason the device rejected a management telegram. A strict device
/// answers most rejections by simply not responding (as a real device would
/// drop a malformed or unauthorized request), but the reason is surfaced for
/// tests and the event log.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceError {
    /// A management verb arrived without an open transport connection.
    #[error("management telegram with no open connection")]
    NotConnected,
    /// A write was attempted without sufficient authorization.
    #[error("unauthorized: access level {level} insufficient")]
    Unauthorized {
        /// The current access level.
        level: u8,
    },
    /// A property access referenced an unknown object or PID.
    #[error("no property: object {object} pid {pid}")]
    NoProperty {
        /// The object index.
        object: u8,
        /// The PID.
        pid: u8,
    },
    /// A write to a read-only property.
    #[error("property object {object} pid {pid} is read-only")]
    ReadOnlyProperty {
        /// The object index.
        object: u8,
        /// The PID.
        pid: u8,
    },
    /// A load-state control write was invalid.
    #[error("load-state control rejected: {0}")]
    LoadControl(String),
    /// A memory write was rejected by the memory model.
    #[error("memory rejected: {0}")]
    Memory(#[from] MemoryError),
    /// The APDU was malformed for its service.
    #[error("malformed {service}: {detail}")]
    Malformed {
        /// The service name.
        service: String,
        /// What was wrong.
        detail: String,
    },
    /// A telegram violated a System 7 wire constraint (standard frame only, at
    /// most 12 memory octets). A real device refuses such a frame.
    #[error("wire-strictness violation: {detail}")]
    WireStrictness {
        /// What constraint was violated.
        detail: String,
    },
    /// A KNX Data Secure frame was refused by an activated device (wrong MAC,
    /// stale/replayed sequence, or a plain access to a protected function).
    /// A real activated device drops such a frame (spec §12.2).
    #[error("secure refused: {0}")]
    Secure(#[from] crate::secure::SecureError),
}

/// One loadable object's runtime state: its LSM plus its assigned segment base.
#[derive(Debug, Clone)]
struct ObjectState {
    lsm: LoadStateMachine,
    /// The segment base this object reports via `PID_TABLE_REFERENCE` (up to
    /// 24-bit; a capable 07B0 object places its segment above 0xFFFF).
    base: u32,
    #[allow(dead_code)] // retained for logging / future viz
    descriptor: LoadableObject,
}

/// Construction-time overrides that select and tune a device's mask profile.
///
/// Supplied by the config layer. When `mask` is `None` the mask comes from the
/// product's `MaskVersion`. `lsm_access` and `bcu_key` apply only to a System 7
/// device.
#[derive(Debug, Clone, Default)]
pub struct ProfileOverrides {
    /// An explicit mask override (`"0705"`, `"MV-07B0"`, ...). `None` = use the
    /// product's declared mask.
    pub mask: Option<String>,
    /// The System 7 LSM realisation to present.
    pub lsm_access: profile::LsmAccess,
    /// The System 7 BCU key required for memory access, or `None` for free
    /// access.
    pub bcu_key: Option<u32>,
    /// Whether the device starts in KNX programming mode. A device in
    /// programming mode answers the broadcast `A_IndividualAddress_Read`, which
    /// is how `bussard assign` and `bussard viz --watch-prog` discover it.
    /// Defaults to `false` (a normal, un-programmed device is silent to the
    /// broadcast read).
    pub prog_mode: bool,
    /// KNX Data Secure activation. `None` (the default) leaves the device plain
    /// (existing devices unaffected). `Some` marks the device security-ACTIVATED
    /// with a synthetic tool key and starting sequence numbers, so all management
    /// access must ride A_SecureData (spec §6.4, §12.2).
    pub secure: Option<SecureActivation>,
}

/// Per-device KNX Data Secure activation parameters (spec §12.2). All key
/// material is synthetic; it never comes from a user file.
#[derive(Debug, Clone)]
pub struct SecureActivation {
    /// The synthetic 16-byte tool key.
    pub tool_key: crate::secure::Key16,
    /// The device's initial send sequence (for wrapping responses, spec §5.8).
    pub initial_tx_seq: u64,
    /// The device's initial receive-freshness floor (spec §5.9): a first inbound
    /// frame must strictly exceed this.
    pub initial_rx_seq: u64,
}

/// The runtime state of a System 7 device's three parallel load-state machines
/// plus the memory-region layout it was built with.
#[derive(Debug, Clone)]
struct Sys7Runtime {
    /// The System 7 sub-profile (mask, LSM access, memory map, key, hw type).
    profile: profile::Sys7Profile,
    /// The three (or more) parallel LSMs, keyed by LSM index (1, 2, 3, [5]).
    lsms: BTreeMap<u8, Sys7LoadStateMachine>,
}

/// A strict KNX device (System B or System 7, per its [`Profile`]).
pub struct Device {
    address: IndividualAddress,
    /// The mask profile: System B or System 7 behaviour.
    profile: Profile,
    /// System 7 runtime (the three LSMs + layout); `None` on a System B device.
    sys7: Option<Sys7Runtime>,
    /// Interface objects keyed by object index (0 = device object).
    objects: BTreeMap<u8, InterfaceObject>,
    /// Loadable-object runtime state keyed by LSM index.
    loadables: BTreeMap<u8, ObjectState>,
    memory: Memory,
    /// Access level (0 = highest/unlocked). Starts locked at 15 until authorize.
    access_level: u8,
    connected: bool,
    /// Sequence number for the next connected response.
    tx_seq: u8,
    /// The **expected** receive sequence number for the next numbered data
    /// telegram (NDT) from the tool. The transport layer numbers NDTs mod 16; a
    /// Style 3 device accepts only the expected sequence, re-acknowledges
    /// (without reprocessing) a retransmit of the one it just ACKed, and
    /// answers anything else with `T_NAK`. See the `transport` module.
    rx_seq: u8,
    /// The device's per-connection numbered-exchange budget: after this many
    /// accepted NDTs on **one** L4 connection, the device drops the connection
    /// (stops answering, as a real connection-oriented device does when its
    /// per-connection resource budget is exhausted). `None` = unlimited (the
    /// default, so existing tests and captures are unaffected). Reset per
    /// connection on `T_Connect`. Modelled after the KNX Virtual DA.tp device,
    /// which drops a long-held L4 connection after ~35 exchanges.
    l4_exchange_budget: Option<u32>,
    /// Numbered exchanges accepted on the **current** L4 connection, reset to 0
    /// on every `T_Connect`. Metered against [`Device::l4_exchange_budget`].
    l4_exchanges: u32,
    /// The Style 3 connection state: partner, timers, the response waiting
    /// for its `T_ACK` (see the `transport` module).
    l4: transport::L4Session,
    /// The runtime group-communication routing, reconstructed from the device's
    /// own flashed tables once every loadable object reaches `Loaded`. `None`
    /// while the device is not fully loaded (an unloaded device is silent on the
    /// group side). Rebuilt after each successful download.
    group_comm: Option<group_comm::GroupComm>,
    /// Whether the device is in KNX programming mode. When `true` the device
    /// answers the broadcast `A_IndividualAddress_Read` with its own address.
    /// Kept in sync with the object-0 `PID_PROGMODE` property: a tool writing
    /// that property (as ETS/`bussard assign` do) flips this bit, and the
    /// initial value comes from [`ProfileOverrides::prog_mode`].
    prog_mode: bool,
    /// The per-device KNX Data Secure session when the device is
    /// security-ACTIVATED (spec §6.1). `None` = plain device (the default), which
    /// leaves every existing device and test unchanged. `Some` = every management
    /// access must ride A_SecureData; a plain access to a protected function is
    /// refused (spec §6.4, §12.2).
    secure: Option<crate::secure::DataSecureSession>,
    /// The KNX Data Secure security interface object (IOT 17), present exactly
    /// when the device is security-activated. Served through the extended
    /// property services (see [`security_object`]).
    security_object: Option<SecurityObject>,
    /// The KNXnet/IP parameter object as the extended property services reach
    /// it (object type 11, instance 1), on a simulated IP interface (bussard
    /// issue #391). `None` on every other device.
    knxnet_by_type: Option<InterfaceObject>,
    /// Further interface objects the extended property services reach by
    /// object type (instance 1), keyed by type: the vendor object of a
    /// property-only device (bussard issue #390, the IPS 300 SREG's object
    /// type 50001). Empty on every other device.
    typed_objects: BTreeMap<u16, InterfaceObject>,
    /// How many tunnelling addresses (PID 53) the KNXnet/IP parameter object
    /// holds at most, as its property description says.
    knxnet_slots: u16,
    /// The KNXnet/IP Secure properties of a simulated KNX IP interface
    /// (bussard issue #398), present with the KNXnet/IP parameter object.
    ip_secure: Option<ip_secure::IpSecureObject>,
    /// The process time (seconds) reported in the `A_Restart_Response` to a
    /// factory reset (erase code 7).
    restart_process_time_s: u16,
    /// The largest segment an allocation may ask for before it fails
    /// (Configuration Procedures §3.5.1.2); `None` allocates any size. See
    /// [`Device::with_max_allocation`].
    max_allocation: Option<u32>,
    events: std::sync::Arc<dyn EventSink>,
}

impl Device {
    /// Build a device at `address` from parsed product data, with an initial
    /// load state applied to every loadable object. The mask profile comes from
    /// the product's declared `MaskVersion`; System 7 devices default to a
    /// memory-mapped LSM and free access.
    ///
    /// Panics only via [`Device::from_product_with_overrides`] returning `Err`
    /// for an unmodelled mask; `from_product` unwraps that into a System B
    /// fallback so existing callers keep the pre-profile behaviour. Prefer
    /// [`Device::from_product_with_overrides`] for explicit control.
    pub fn from_product(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        events: std::sync::Arc<dyn EventSink>,
    ) -> Self {
        // The pre-profile entry point: derive the profile from the product mask,
        // defaulting to System B when the mask is absent or unmodelled so the
        // DA.tp calibration path is unchanged.
        match Self::from_product_with_overrides(
            address,
            product,
            initial_state,
            ProfileOverrides::default(),
            events.clone(),
        ) {
            Ok(dev) => dev,
            // Fall back to an explicit System B profile for an unmodelled mask,
            // preserving the pre-profile behaviour for callers that pass an
            // exotic product.
            Err(_) => Self::from_product_with_overrides(
                address,
                product,
                initial_state,
                ProfileOverrides {
                    mask: Some("07B0".into()),
                    ..Default::default()
                },
                events,
            )
            .expect("System B fallback always builds"),
        }
    }

    /// Build a device, selecting and tuning its mask profile from `overrides`.
    ///
    /// Returns `Err` with a human reason when the effective mask is a family the
    /// simulator does not model (only System B `0x07B0` and System 7 `0x0700` /
    /// `0x0701` / `0x0705` are modelled), because a strict simulator refuses to pretend to
    /// be a device generation it does not implement.
    pub fn from_product_with_overrides(
        address: IndividualAddress,
        product: &ProductData,
        initial_state: LoadState,
        overrides: ProfileOverrides,
        events: std::sync::Arc<dyn EventSink>,
    ) -> Result<Self, String> {
        // Resolve the effective mask: override wins, else the product's declared
        // MaskVersion, else default to System B (the DA.tp calibration default).
        let mask = match &overrides.mask {
            Some(s) => {
                profile::parse_mask(s).ok_or_else(|| format!("unparseable mask override {s:?}"))?
            }
            None => profile::parse_mask(&product.mask_version).unwrap_or(0x07B0),
        };
        let profile = match profile::mask_family(mask) {
            profile::MaskFamily::SystemB => Profile::SystemB { mask },
            profile::MaskFamily::System7 => Profile::System7(profile::Sys7Profile {
                mask,
                lsm_access: overrides.lsm_access,
                mm_lsm: profile::MemoryMappedLsm::default(),
                memory_map: profile::Sys7MemoryMap::default(),
                bcu_key: overrides.bcu_key,
                // Prefer the value the app's own CompareProp preflight expects
                // (a factory device holds exactly that); fall back to the
                // derived default only when the procedure carries no compare.
                hardware_type: product
                    .hardware_type_marker
                    .as_deref()
                    .and_then(|m| <[u8; 10]>::try_from(m).ok())
                    .unwrap_or_else(|| profile::default_hardware_type(product.application_number)),
            }),
            // A property-only procedure on mask 0021 (bussard issue #390): the
            // Jung IPS 300 SREG KNX IP interface.
            profile::MaskFamily::Other if mask == 0x0021 && product.property_only => {
                return Ok(Self::build_property_device(
                    address,
                    product,
                    Profile::SystemB { mask },
                    overrides.prog_mode,
                    events,
                ));
            }
            profile::MaskFamily::Other => {
                return Err(format!(
                    "mask 0x{mask:04x} is not a modelled family (only System B 07B0 and \
                     System 7 0705/0701 are simulated)"
                ));
            }
        };
        // Build the Data Secure session up front (spec §6.1): `None` keeps the
        // device plain (the default), `Some` marks it security-ACTIVATED.
        let secure = overrides.secure.map(|a| {
            crate::secure::DataSecureSession::new(a.tool_key, a.initial_tx_seq, a.initial_rx_seq)
        });
        if profile.is_system7() {
            Ok(Self::build_system7(
                address,
                product,
                initial_state,
                profile,
                overrides.prog_mode,
                secure,
                events,
            ))
        } else {
            Ok(Self::build_system_b(
                address,
                product,
                initial_state,
                profile,
                overrides.prog_mode,
                secure,
                events,
            ))
        }
    }

    /// Overrides (or adds) a read-only property value on interface object
    /// `object`: the device identity a tool reads before it downloads
    /// (hardware type PID 78, order info PID 15, ...) when the product data
    /// does not say what the real hardware answers (the ETS sweep, bussard
    /// epic #419). An unknown object index is ignored.
    pub fn with_property(mut self, object: u8, pid: u8, value: Vec<u8>) -> Self {
        if let Some(obj) = self.objects.get_mut(&object) {
            obj.set_property(pid, Property::read_only(value));
        }
        self
    }

    /// Sets the device's per-connection numbered-exchange budget (builder-style).
    ///
    /// After `budget` accepted NDTs on one L4 connection the device drops the
    /// connection — stops answering — modelling a real connection-oriented
    /// device's per-connection resource limit (KNX Virtual drops at ~35). `None`
    /// leaves it unlimited (the default). See [`Device::l4_exchange_budget`].
    pub fn with_l4_exchange_budget(mut self, budget: Option<u32>) -> Self {
        self.l4_exchange_budget = budget;
        self
    }

    /// Gives the device a KNXnet/IP parameter object (interface object type
    /// 11) at the next free object index, serving `params`: the simulated KNX
    /// IP interface of bussard issue #391.
    pub fn with_knxnet_object(self, params: &knxnet_object::KnxnetParameters) -> Self {
        self.with_knxnet(params, true)
    }

    /// Gives the device a KNXnet/IP parameter object, reachable by object
    /// type 11 and instance 1 through `A_PropertyExtValue_Read` and, when
    /// `listed`, also at the next object index for the plain services. An
    /// unlisted object models the Jung IPS 300 SREG (mask 0021, bussard issue
    /// #391), whose object-index walk shows a device object and an address
    /// table only while ETS programs the KNXnet/IP parameters by object type.
    pub fn with_knxnet(mut self, params: &knxnet_object::KnxnetParameters, listed: bool) -> Self {
        if listed {
            let index = self
                .objects
                .keys()
                .next_back()
                .map_or(0, |last| last.saturating_add(1));
            self.objects.insert(index, params.object());
        }
        // A property-only device (bussard issue #390) already has the object
        // with the properties its procedure writes: those stay, next to the
        // configured KNXnet/IP values.
        let mut object = params.object();
        if let Some(existing) = &self.knxnet_by_type {
            for pid in existing.pids() {
                if !object.has_property(pid)
                    && let Some(prop) = existing.property(pid)
                {
                    object.set_property(pid, prop.clone());
                }
            }
        }
        self.knxnet_by_type = Some(object);
        self.knxnet_slots = params.tunnel_slots;
        if self.ip_secure.is_none() {
            self.ip_secure = Some(ip_secure::IpSecureObject::new());
        }
        self
    }

    /// Puts the device's security object in factory state (security mode
    /// off), for a device that takes Data Secure tool access under its FDSK:
    /// a KNX IP interface before IP Secure is switched on (bussard issue
    /// #398). No effect on a plain device.
    pub fn with_factory_security(mut self) -> Self {
        if self.security_object.is_some() {
            self.security_object = Some(SecurityObject::new_factory());
        }
        self
    }

    /// The KNXnet/IP Secure properties, on a simulated KNX IP interface.
    pub fn ip_secure(&self) -> Option<&ip_secure::IpSecureObject> {
        self.ip_secure.as_ref()
    }

    /// The tunnelling addresses (`PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`), raw,
    /// in slot order.
    fn tunnel_addresses(&self) -> Vec<u16> {
        self.knxnet_property(53)
            .unwrap_or_default()
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    /// cEMI local device management on the device a KNXnet/IP server serves
    /// (bussard issue #398): `M_PropRead.req`, `M_PropWrite.req` and
    /// `M_Reset.req` (KNX 3/6/3 §4.1.7) on the objects reached by type (the
    /// KNXnet/IP parameter object, its Secure properties, a vendor object).
    /// `body` is the cEMI frame from the message code on; the answer is the
    /// confirmation frame (`M_PropRead.con`, `M_PropWrite.con`), or `None`
    /// for `M_Reset.req` and anything else.
    pub fn local_management(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let (&mc, rest) = body.split_first()?;
        if mc == 0xF1 {
            self.apply_ip_secure();
            return None;
        }
        if !(mc == 0xFC || mc == 0xF6) || rest.len() < 6 {
            return None;
        }
        let object_type = u16::from_be_bytes([rest[0], rest[1]]);
        let instance = u32::from(rest[2]);
        let pid = u32::from(rest[3]);
        let count = rest[4] >> 4;
        let start = (u16::from(rest[4] & 0x0F) << 8) | u16::from(rest[5]);
        let packed = (instance << 12) | pid;
        let mut request = object_type.to_be_bytes().to_vec();
        request.extend_from_slice(&packed.to_be_bytes()[1..]);
        request.push(count);
        request.extend_from_slice(&start.to_be_bytes());
        request.extend_from_slice(&rest[6..]);
        let write = mc == 0xF6;
        let answer = self.ip_secure.as_mut().and_then(|ip| {
            if write {
                ip.write(&request)
            } else {
                ip.read(&request)
            }
        });
        let answer = match answer {
            Some(a) => Some(a),
            None if object_type == knxnet_object::IOT_KNXNET_IP_PARAMETER => {
                let slots = self.knxnet_slots;
                let obj = self.knxnet_by_type.as_mut()?;
                if write {
                    knxnet_object::ext_write(obj, &request, slots).map(|(a, _)| a)
                } else {
                    knxnet_object::typed_ext_read(object_type, obj, &request)
                }
            }
            None => {
                let obj = self.typed_objects.get_mut(&object_type)?;
                if write {
                    knxnet_object::typed_ext_write(object_type, obj, &request)
                } else {
                    knxnet_object::typed_ext_read(object_type, obj, &request)
                }
            }
        }?;
        // The extended answer: header(5) count start(2) then data (read) or
        // the return code (write).
        let header = &rest[..4];
        let mut out = vec![if write { 0xF5 } else { 0xFB }];
        out.extend_from_slice(header);
        if write {
            let rc = answer.get(8).copied().unwrap_or(1);
            if rc == 0 {
                out.extend_from_slice(&rest[4..6]);
            } else {
                out.extend_from_slice(&[rest[4] & 0x0F, rest[5], 0x07]);
            }
        } else {
            let served = answer.get(5).copied().unwrap_or(0);
            if served == 0 {
                out.extend_from_slice(&[rest[4] & 0x0F, rest[5], 0x07]);
            } else {
                out.push((served << 4) | (rest[4] & 0x0F));
                out.push(rest[5]);
                out.extend_from_slice(answer.get(8..).unwrap_or_default());
            }
        }
        Some(out)
    }

    /// The master reset of a simulated KNX IP interface: its KNXnet/IP Secure
    /// properties take effect.
    pub(super) fn apply_ip_secure(&mut self) {
        let tunnels = self.tunnel_addresses();
        let table = self.knxnet_property(79).map(<[u8]>::to_vec);
        let own = self.address.raw();
        if let Some(ip) = self.ip_secure.as_mut() {
            ip.apply(own, &tunnels, table.as_deref());
        }
    }

    /// The object index of the listed KNXnet/IP parameter object, if any.
    pub(super) fn knxnet_index(&self) -> Option<u8> {
        self.objects
            .iter()
            .find(|(_, o)| knxnet_object::is_knxnet(o))
            .map(|(i, _)| *i)
    }

    /// Copies PID `pid` of the KNXnet/IP parameter object from the copy just
    /// written (`from_listed`: the listed object, else the one reached by
    /// type) to the other, so both services see one store.
    pub(super) fn knxnet_sync(&mut self, pid: u8, from_listed: bool) {
        let Some(index) = self.knxnet_index() else {
            return;
        };
        let value = if from_listed {
            self.objects
                .get(&index)
                .and_then(|o| o.property(pid))
                .map(|p| p.value.clone())
        } else {
            self.knxnet_by_type
                .as_ref()
                .and_then(|o| o.property(pid))
                .map(|p| p.value.clone())
        };
        let Some(value) = value else {
            return;
        };
        let target = if from_listed {
            self.knxnet_by_type.as_mut()
        } else {
            self.objects.get_mut(&index)
        };
        if let Some(prop) = target.and_then(|o| o.property_mut(pid)) {
            prop.value = value;
        }
    }

    /// The value of PID `pid` of the KNXnet/IP parameter object (for tests and
    /// observability).
    pub fn knxnet_property(&self, pid: u8) -> Option<&[u8]> {
        self.knxnet_by_type
            .as_ref()
            .and_then(|o| o.property(pid))
            .map(|p| p.value.as_slice())
    }

    /// The device's individual address.
    pub fn address(&self) -> IndividualAddress {
        self.address
    }

    /// Whether the device is currently in KNX programming mode.
    pub fn prog_mode(&self) -> bool {
        self.prog_mode
    }

    /// Set the device's programming-mode bit at runtime and keep the object-0
    /// `PID_PROGMODE` property in sync so a subsequent property read agrees. This
    /// is the programmatic toggle a test or embedding harness uses; the wire path
    /// (a tool writing `PID_PROGMODE`) flows through the same state via
    /// [`Device::on_property_write`].
    pub fn set_prog_mode(&mut self, on: bool) {
        self.sync_prog_mode(on);
    }

    /// Update the programming-mode bit and the object-0 `PID_PROGMODE` property
    /// together, emitting a [`Event::ProgModeChanged`] only on an actual change.
    fn sync_prog_mode(&mut self, on: bool) {
        if let Some(device_object) = self.objects.get_mut(&0)
            && let Some(prop) = device_object.property_mut(PID_PROGMODE)
        {
            prop.value = vec![u8::from(on)];
        }
        if self.prog_mode != on {
            self.prog_mode = on;
            self.emit(Event::ProgModeChanged {
                device: self.address,
                on,
            });
        }
    }

    /// The device's answer to a broadcast `A_IndividualAddress_Read`: an
    /// `A_IndividualAddress_Response` whose **source** is the device's own
    /// address and which carries no payload, framed as an `L_Data.ind` to the
    /// broadcast group address `0/0/0`.
    ///
    /// Returns `None` unless the device is in programming mode — only a device
    /// in programming mode answers the broadcast read (spec: individual-address
    /// read/response service).
    pub fn individual_address_response(&self) -> Option<CemiLData> {
        if !self.prog_mode {
            return None;
        }
        let apci10 = Apci::IndividualAddressResponse.to_u10();
        Some(CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            // Broadcast: group destination bit set (bit 7) + hop count 6.
            ctrl2: 0xe0,
            source: self.address,
            // The broadcast group address 0/0/0.
            dest: 0x0000,
            // TPCI unnumbered data (00) with the APCI high bits, then the APCI
            // low byte; no payload.
            tpdu: vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8],
        })
    }

    /// Adopt `new_address` from a broadcast `A_IndividualAddress_Write`.
    ///
    /// Per the individual-address write service, **only a device in programming
    /// mode** applies the broadcast; every other device ignores it. Returns
    /// whether this device adopted the address. The service defines no response,
    /// so the caller sends nothing back — the tool verifies by connecting to the
    /// new address (which is what `bussard assign` does).
    ///
    /// The device stays in programming mode afterwards, as a real device does:
    /// the tool clears it explicitly by writing `PID_PROGMODE = 0`.
    pub fn adopt_individual_address(&mut self, new_address: IndividualAddress) -> bool {
        if !self.prog_mode {
            return false;
        }
        if self.address != new_address {
            self.emit(Event::AddressChanged {
                device: self.address,
                new_address,
            });
            self.address = new_address;
        }
        true
    }

    /// The current load state of a loadable object (by LSM index). On a System 7
    /// device the state lives in the parallel System 7 LSM; on System B it lives
    /// in the object's `LoadStateMachine`.
    pub fn load_state(&self, lsm_index: u8) -> Option<LoadState> {
        if let Some(s7) = &self.sys7 {
            return s7.lsms.get(&lsm_index).map(|m| m.state());
        }
        self.loadables.get(&lsm_index).map(|o| o.lsm.state())
    }

    /// The device's mask profile (System B or System 7).
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Read-only view of device memory (for tests/observability).
    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    /// The reconstructed runtime group-communication routing, if the device is
    /// loaded and linked (for tests/observability).
    pub fn group_comm(&self) -> Option<&group_comm::GroupComm> {
        self.group_comm.as_ref()
    }

    /// The segment base a loadable object reports via `PID_TABLE_REFERENCE`.
    ///
    /// System B table objects (address/association/com-object tables) live in the
    /// low 16-bit region, so the group-comm table parse takes a `u16` base; a
    /// base above 0xFFFF here would be an application segment, not a routing table.
    fn base_of(&self, lsm_index: u8) -> Option<u16> {
        self.loadables.get(&lsm_index).map(|o| o.base as u16)
    }

    /// The 8-octet `PID_MCB_TABLE` entry a loadable object reports over its
    /// resident segment, for tests/observability — the same bytes the wire PID 27
    /// read answers (see [`Device::mcb_entry_for`]). `None` when the object has no
    /// written segment (a blank object answers "no MCB entry").
    ///
    /// This is what the MCB-CRC re-download skip reads: a tool that computes the
    /// same size+CRC over the image it is about to stream can compare it here and
    /// skip the re-stream when they match. A blank device returns `None`, so the
    /// skip is never taken and the object full-streams.
    pub fn mcb_entry(&self, object: u8) -> Option<Vec<u8>> {
        self.mcb_entry_for(object)
    }

    /// The 8-octet `PID_MCB_TABLE` entry this object would report: an integrity
    /// block over the bytes currently stored in the object's allocated segment.
    ///
    /// Returns `None` if the object has no allocated segment (nothing written),
    /// which a tool reads as "no MCB entry" — but after a load the segment exists,
    /// so a verify step gets a real CRC over exactly the bytes the download wrote.
    fn mcb_entry_for(&self, object: u8) -> Option<Vec<u8>> {
        // The MCB covers the bytes the tool actually streamed (the loaded image),
        // which may be shorter than the allocated segment — a tool that writes a
        // compact table into a larger allocation must still verify against just
        // those bytes. Use the written span, not the full allocation.
        let bytes = self.memory.written_span(object)?;
        Some(mcb::mcb_entry(&bytes).to_vec())
    }

    fn emit(&self, event: Event) {
        self.events.emit(event);
    }

    /// Handle a full inbound cEMI telegram, updating state and producing
    /// responses. Control frames (T_Connect/T_Disconnect/T_ACK) are handled
    /// here; data telegrams are dispatched to [`Device::handle_apdu`].
    pub fn handle_cemi(&mut self, cemi: &CemiLData) -> Result<DeviceReaction, DeviceError> {
        self.handle_cemi_at(cemi, std::time::Instant::now())
    }

    /// [`handle_cemi`](Self::handle_cemi) at the instant `now`, which the
    /// transport timers measure against (tests pass a later instant to run
    /// them).
    pub fn handle_cemi_at(
        &mut self,
        cemi: &CemiLData,
        now: std::time::Instant,
    ) -> Result<DeviceReaction, DeviceError> {
        if cemi.tpdu.is_empty() {
            return Ok(DeviceReaction::default());
        }
        let tpci = Tpci::from_byte(cemi.tpdu[0]);
        // The connection timeout runs before the frame is handled, in case
        // the bus did not tick in time (03_03_04 §5.4.3 E16).
        let expired = self.expire_l4(now);
        let mut reaction = match tpci {
            Tpci::Connect | Tpci::Disconnect | Tpci::Ack(_) | Tpci::Nak(_) => {
                self.handle_transport_control(cemi, tpci, now)
            }
            Tpci::DataUnnumbered => {
                // Unnumbered (broadcast/individual) data carries no L4 sequence.
                let apdu = Apdu::parse(&cemi.tpdu).ok_or(DeviceError::Malformed {
                    service: "APDU".into(),
                    detail: "too short".into(),
                })?;
                self.handle_apdu(cemi, &apdu)?
            }
            Tpci::DataConnected(seq) => self.handle_numbered_data(cemi, seq, now)?,
        };
        if !expired.is_empty() {
            reaction.responses.splice(0..0, expired);
        }
        Ok(reaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::test_support::*;

    #[test]
    fn test_connectionless_descriptor_and_property_reads_are_answered_unnumbered()
    -> Result<(), Box<dyn std::error::Error>> {
        // ETS 6 probes a KNX Secure capable device with unnumbered
        // A_DeviceDescriptor_Read and A_PropertyValue_Read before it connects.
        let mut dev = system_b_device()?;
        let tool = IndividualAddress(0x11FE);
        let dest = dev.address.raw();
        let req = |tpdu: Vec<u8>| CemiLData {
            message_code: crate::wire::cemi::MessageCode::LDataReq,
            ctrl1: 0xBC,
            ctrl2: 0x60,
            source: tool,
            dest,
            tpdu,
        };
        let r = dev.handle_cemi(&req(vec![0x03, 0x00]))?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(r.responses[0].tpdu[0] & 0xFC, 0x00, "unnumbered response");
        assert_eq!(
            &r.responses[0].tpdu[..2],
            &[0x03, 0x40],
            "A_DeviceDescriptor_Response"
        );
        // PID 56 (max APDU length) of object 0.
        let r = dev.handle_cemi(&req(vec![0x03, 0xD5, 0x00, 0x38, 0x10, 0x01]))?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(r.responses[0].tpdu[0] & 0xFC, 0x00, "unnumbered response");
        // Every other service still needs a connection.
        let err = dev.handle_cemi(&req(vec![0x03, 0xD1, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]));
        assert!(matches!(err, Err(DeviceError::NotConnected)));
        // A later connection starts at sequence 0, untouched by the probes.
        dev.handle_cemi(&req(vec![0x80]))?;
        let r = dev.handle_cemi(&req(vec![0x43, 0x00]))?;
        let ndt = r
            .responses
            .iter()
            .find(|c| c.tpdu.len() > 1)
            .ok_or("no response")?;
        assert_eq!(
            ndt.tpdu[0] & 0x3C,
            0x00,
            "first connected response under sequence 0"
        );
        Ok(())
    }

    #[test]
    fn test_individual_address_response_only_when_in_prog_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        // A device NOT in programming mode is silent to the broadcast read.
        let quiet = prog_device(false)?;
        assert!(quiet.individual_address_response().is_none());

        // A device in programming mode answers with an A_IndividualAddress_Response
        // whose source is its own address and dest is the broadcast group 0/0/0.
        let programming = prog_device(true)?;
        let resp = programming
            .individual_address_response()
            .ok_or("device in prog mode must answer")?;
        assert_eq!(resp.message_code, MessageCode::LDataInd);
        assert_eq!(resp.source, IndividualAddress::new(1, 1, 2));
        assert_eq!(resp.dest, 0x0000);
        assert!(resp.is_group(), "broadcast frames carry the group bit");
        let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
        assert_eq!(Apci::from_u10(apci10), Apci::IndividualAddressResponse);
        Ok(())
    }

    #[test]
    fn test_pid_progmode_write_toggles_prog_mode() -> Result<(), Box<dyn std::error::Error>> {
        // Writing PID_PROGMODE over the wire (as ETS/`bussard assign` do) flips the
        // runtime bit: 1 enters programming mode, 0 leaves it.
        let mut dev = prog_device(false)?;
        connect(&mut dev)?;
        // Authorize (free access) so property writes are accepted.
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        assert!(!dev.prog_mode());

        // A_PropertyValue_Write obj0 PID_PROGMODE count=1 start=1 value=01.
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x00, PID_PROGMODE, 0x10, 0x01, 0x01]))?;
        assert!(dev.prog_mode(), "writing PID_PROGMODE=1 enters prog mode");
        assert!(
            dev.individual_address_response().is_some(),
            "now answers the broadcast read"
        );

        // Writing 0 leaves programming mode again (how `assign` clears it).
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x00, PID_PROGMODE, 0x10, 0x01, 0x00]))?;
        assert!(!dev.prog_mode(), "writing PID_PROGMODE=0 leaves prog mode");
        assert!(dev.individual_address_response().is_none());
        Ok(())
    }

    #[test]
    fn test_set_prog_mode_syncs_property() -> Result<(), Box<dyn std::error::Error>> {
        // The programmatic toggle updates both the bit and the PID_PROGMODE
        // property value so a subsequent property read agrees.
        let mut dev = prog_device(false)?;
        dev.set_prog_mode(true);
        assert!(dev.prog_mode());
        let prop = dev
            .objects
            .get(&0)
            .and_then(|io| io.property(PID_PROGMODE))
            .ok_or("device object has PID_PROGMODE")?;
        assert_eq!(prop.value, vec![0x01]);
        Ok(())
    }

    #[test]
    fn test_knxnet_object_serves_the_ip_interface_read_side()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bussard issue #391: a simulated IP interface answers the object-type
        // probe with type 11 at the next index and serves its properties as
        // arrays, read-only.
        let params = knxnet_object::KnxnetParameters::dhcp(0x11C8, vec![0x1116, 0x1117, 0x1118]);
        let mut dev = system_b_device()?.with_knxnet_object(&params);
        let index = *dev.objects.keys().next_back().ok_or("objects")?;
        connect(&mut dev)?;
        let read = |dev: &mut Device, pid: u8, count: u8, start: u8| {
            dev.handle_cemi(&data(dev, 0x3D5, &[index, pid, count << 4, start]))
                .map(|r| (r.responses[0].tpdu[4] >> 4, prop_response_value(&r)))
        };
        assert_eq!(read(&mut dev, 1, 1, 1)?, (1, vec![0, 11]));
        assert_eq!(read(&mut dev, 53, 1, 0)?, (1, vec![0, 3]), "three tunnels");
        assert_eq!(
            read(&mut dev, 53, 3, 1)?,
            (3, vec![0x11, 0x16, 0x11, 0x17, 0x11, 0x18])
        );
        assert_eq!(
            read(&mut dev, 53, 2, 3)?,
            (0, vec![]),
            "past the end is refused"
        );
        assert_eq!(read(&mut dev, 57, 1, 1)?, (1, vec![192, 168, 1, 74]));
        assert_eq!(read(&mut dev, 55, 1, 1)?, (1, vec![0x04]), "DHCP");
        assert_eq!(
            read(&mut dev, 92, 1, 1)?,
            (0, vec![]),
            "no Secure PID is served"
        );
        let (n, name) = read(&mut dev, 76, 10, 1)?;
        assert_eq!((n, &name[..7]), (10, &b"knx-sim"[..]));
        // Read-only: a write is refused and the value stays.
        let write = dev.handle_cemi(&data(&dev, 0x3D7, &[index, 52, 0x11, 0x01, 0x11, 0x05]));
        assert!(write.is_err(), "an unauthorized write is refused");
        assert_eq!(read(&mut dev, 52, 1, 1)?, (1, vec![0x11, 0xC8]));
        Ok(())
    }

    #[test]
    fn test_knxnet_object_takes_writes_on_both_services() -> Result<(), Box<dyn std::error::Error>>
    {
        // Bussard issue #391, the write side: the writable PIDs take plain and
        // extended writes into one store, PID 53 grows up to its tunnel slots,
        // and both description services say so.
        let mut params = knxnet_object::KnxnetParameters::dhcp(0x11C8, vec![0x1116, 0x1117]);
        params.tunnel_slots = 4;
        let mut dev = system_b_device()?.with_knxnet_object(&params);
        let index = *dev.objects.keys().next_back().ok_or("objects")?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]))?;
        // A_PropertyValue_Write PID 53: the count to 3, then element 3.
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &[index, 53, 0x10, 0x00, 0x00, 0x03]))?;
        assert_eq!(r.responses[0].tpdu[4] >> 4, 1, "count taken");
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &[index, 53, 0x10, 0x03, 0x11, 0x1E]))?;
        assert_eq!(r.responses[0].tpdu[4] >> 4, 1, "element 3 taken");
        assert_eq!(
            dev.knxnet_property(53),
            Some(&[0x11, 0x16, 0x11, 0x17, 0x11, 0x1E][..]),
            "the extended services see the plain write"
        );
        // Five elements do not fit four slots: refused with count 0.
        let r = dev.handle_cemi(&data(&dev, 0x3D7, &[index, 53, 0x10, 0x00, 0x00, 0x05]))?;
        assert_eq!(r.responses[0].tpdu[4] >> 4, 0);
        // A_PropertyExtValue_WriteCon PID 76 "Beta", elements 1 to 4.
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CE,
            &[0x00, 0x0B, 0x00, 0x10, 76, 4, 0, 1, b'B', b'e', b't', b'a'],
        ))?;
        assert_eq!(r.responses[0].tpdu[1], 0xCF);
        assert_eq!(r.responses[0].tpdu.last(), Some(&0), "return code 0");
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[index, 76, 0x40, 0x01]))?;
        assert_eq!(prop_response_value(&r), b"Beta", "the plain read sees it");
        // PID 52 is read-only: return code 1.
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CE,
            &[0x00, 0x0B, 0x00, 0x10, 52, 1, 0, 1, 0x11, 0x05],
        ))?;
        assert_eq!(r.responses[0].tpdu.last(), Some(&1));
        // A_PropertyDescription_Read PID 53: writable, four elements.
        let r = dev.handle_cemi(&data(&dev, 0x3D8, &[index, 53, 0]))?;
        let d = &r.responses[0].tpdu;
        assert_eq!(d[1], 0xD9);
        assert_eq!(d[5] & 0x80, 0x80, "writable");
        assert_eq!(u16::from_be_bytes([d[6], d[7]]), 4);
        // A_PropertyExtDescription_Read PID 53, the same.
        let r = dev.handle_cemi(&data(&dev, 0x1D2, &[0x00, 0x0B, 0x00, 0x10, 53, 0, 0]))?;
        let d = &r.responses[0].tpdu;
        assert_eq!(d[1], 0xD3);
        assert_eq!(d[13] & 0x80, 0x80, "writable");
        assert_eq!(u16::from_be_bytes([d[14], d[15]]), 4);
        Ok(())
    }

    #[test]
    fn test_device_object_answers_ext_read_by_type() -> Result<(), Box<dyn std::error::Error>> {
        // ETS reads the manufacturer id of the ABB Modbus RTU gateway as
        // A_PropertyExtValue_Read type 0, instance 1, PID 12 (2026-10-28).
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        let r = dev.handle_cemi(&data(&dev, 0x1CC, &[0x00, 0x00, 0x00, 0x10, 0x0C, 1, 0, 1]))?;
        assert_eq!(r.responses.len(), 1);
        let tpdu = &r.responses[0].tpdu;
        assert_eq!(tpdu[1], 0xCD, "A_PropertyExtValue_Response");
        assert_eq!(tpdu[7], 1, "one element returned");
        assert_eq!(tpdu.len(), 10 + 2, "the two-octet manufacturer id");
        Ok(())
    }

    #[test]
    fn test_unlisted_knxnet_object_answers_by_type_only() -> Result<(), Box<dyn std::error::Error>>
    {
        // The IPS 300 SREG shape (bussard issue #391): the walk does not list
        // object type 11, the extended services reach it by type and instance.
        let params = knxnet_object::KnxnetParameters::dhcp(0x11C8, vec![0x1116, 0x1117]);
        let mut dev = system_b_device()?.with_knxnet(&params, false);
        assert!(
            dev.objects.values().all(|o| o
                .property(interface_object::PID_OBJECT_TYPE)
                .map(|p| p.value.clone())
                != Some(vec![0, 11])),
            "the object-index walk does not list it"
        );
        connect(&mut dev)?;
        // A_PropertyExtValue_Read type 11, instance 1, PID 52, count 1, start 1.
        let r = dev.handle_cemi(&data(&dev, 0x1CC, &[0x00, 0x0B, 0x00, 0x10, 0x34, 1, 0, 1]))?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(r.responses[0].tpdu[1], 0xCD, "A_PropertyExtValue_Response");
        assert_eq!(
            &r.responses[0].tpdu[2..],
            &[0x00, 0x0B, 0x00, 0x10, 0x34, 1, 0, 1, 0x11, 0xC8]
        );
        // The tunnel count, then instance 2 is refused with count 0.
        let r = dev.handle_cemi(&data(&dev, 0x1CC, &[0x00, 0x0B, 0x00, 0x10, 0x35, 1, 0, 0]))?;
        assert_eq!(&r.responses[0].tpdu[7..], &[1, 0, 0, 0, 2]);
        let r = dev.handle_cemi(&data(&dev, 0x1CC, &[0x00, 0x0B, 0x00, 0x20, 0x34, 1, 0, 1]))?;
        assert_eq!(r.responses[0].tpdu[7], 0, "another instance");
        // A plain device only T_ACKs the extended services.
        let mut plain = system_b_device()?;
        connect(&mut plain)?;
        let r = plain.handle_cemi(&data(
            &plain,
            0x1CC,
            &[0x00, 0x0B, 0x00, 0x10, 0x34, 1, 0, 1],
        ))?;
        assert!(
            r.responses.iter().all(|f| f.tpdu.len() == 1),
            "{:?}",
            r.responses
        );
        Ok(())
    }

    /// The IPS 300 SREG's shape (bussard issue #390) as `ProductData`.
    fn property_only_product() -> crate::prod::ProductData {
        let mut pd = crate::testfixtures::synthetic_mdt_sys7_product();
        pd.application_id = "M-0004_A-0016-10-EBD7-O00A6".into();
        pd.mask_version = "MV-0021".into();
        pd.objects.clear();
        pd.hardware_type_marker = None;
        pd.device_compare_props = vec![(78, vec![0, 0, 0, 0x16, 0, 0])];
        pd.typed_props = vec![
            crate::prod::TypedProperty {
                object_type: 11,
                pid: 205,
                compare: None,
                written: true,
            },
            crate::prod::TypedProperty {
                object_type: 50001,
                pid: 211,
                compare: None,
                written: true,
            },
        ];
        pd.property_only = true;
        pd
    }

    #[test]
    fn test_property_only_device_takes_writes_by_type() -> Result<(), Box<dyn std::error::Error>> {
        let pd = property_only_product();
        let sink = std::sync::Arc::new(crate::bus::event::RecordingSink::new());
        let mut dev = Device::from_product_with_overrides(
            IndividualAddress::new(1, 1, 200),
            &pd,
            LoadState::Loaded,
            ProfileOverrides::default(),
            sink,
        )?;
        assert_eq!(dev.profile.mask(), 0x0021);
        connect(&mut dev)?;
        let r = dev.handle_cemi(&data(&dev, 0x3D1, &[0, 0xFF, 0xFF, 0xFF, 0xFF]))?;
        assert!(!r.responses.is_empty(), "authorize answered");
        // The compare the procedure runs: object 0 PID 78.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0, 78, 0x10, 1]))?;
        assert_eq!(prop_response_value(&r), vec![0, 0, 0, 0x16, 0, 0]);
        // PID 205 of type 11: two 4-octet elements, written then read back.
        let mut write = vec![0x00, 0x0B, 0x00, 0x10, 0xCD, 2, 0, 1];
        write.extend_from_slice(&[192, 168, 1, 2, 10, 0, 0, 2]);
        let r = dev.handle_cemi(&data(&dev, 0x1CE, &write))?;
        assert_eq!(
            &r.responses[0].tpdu[1..],
            &[0xCF, 0x00, 0x0B, 0x00, 0x10, 0xCD, 2, 0, 1, 0]
        );
        let r = dev.handle_cemi(&data(&dev, 0x1CC, &[0x00, 0x0B, 0x00, 0x10, 0xCD, 2, 0, 1]))?;
        assert_eq!(&r.responses[0].tpdu[10..], &[192, 168, 1, 2, 10, 0, 0, 2]);
        // The vendor object, type 50001.
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CE,
            &[0xC3, 0x51, 0x00, 0x10, 0xD3, 1, 0, 1, 40],
        ))?;
        assert_eq!(r.responses[0].tpdu.last(), Some(&0));
        // A property the procedure does not write is refused.
        let r = dev.handle_cemi(&data(
            &dev,
            0x1CE,
            &[0x00, 0x0B, 0x00, 0x10, 0x34, 1, 0, 1, 0x11, 0x05],
        ))?;
        assert_eq!(r.responses[0].tpdu.last(), Some(&1));
        // The object walk lists the device object and the address table only.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[2, 1, 0x10, 1]))?;
        assert!(prop_response_value(&r).is_empty());
        Ok(())
    }

    #[test]
    fn test_property_only_product_needs_mask_0021() -> Result<(), Box<dyn std::error::Error>> {
        let mut pd = property_only_product();
        pd.mask_version = "MV-0012".into();
        let sink = std::sync::Arc::new(crate::bus::event::RecordingSink::new());
        assert!(
            Device::from_product_with_overrides(
                IndividualAddress::new(1, 1, 200),
                &pd,
                LoadState::Loaded,
                ProfileOverrides::default(),
                sink,
            )
            .is_err()
        );
        Ok(())
    }
}
