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
    PID_PROGMODE, PID_RUN_STATE_CONTROL, PID_TABLE, PID_TABLE_REFERENCE, Property,
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
    /// telegram (NDT) from the tool. The KNX style-1 rationalised transport layer
    /// numbers NDTs mod 16; a strict device accepts only the expected sequence,
    /// re-acknowledges (without reprocessing) a retransmit of the one it just
    /// ACKed, and ignores anything else. See [`Device::handle_cemi`].
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
    /// The process time (seconds) reported in the `A_Restart_Response` to a
    /// factory reset (erase code 7).
    restart_process_time_s: u16,
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
    /// simulator does not model (only System B `0x07B0` and System 7 `0x0705` /
    /// `0x0701` are modelled), because a strict simulator refuses to pretend to
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
        if let Some(device_object) = self.objects.get_mut(&0) {
            if let Some(prop) = device_object.property_mut(PID_PROGMODE) {
                prop.value = vec![u8::from(on)];
            }
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
        if cemi.tpdu.is_empty() {
            return Ok(DeviceReaction::default());
        }
        let tpci = Tpci::from_byte(cemi.tpdu[0]);
        match tpci {
            Tpci::Connect => {
                self.connected = true;
                self.tx_seq = 0;
                // A fresh transport connection resets both sequence counters to 0
                // (KNX style-1 rationalised: T_Connect restarts the numbering).
                self.rx_seq = 0;
                // A fresh connection also resets the per-connection exchange
                // budget: each L4 connection gets its own allowance, so a tool
                // that periodically reconnects (as ETS does) never exhausts it.
                self.l4_exchanges = 0;
                // Authorization is NOT reset on connect. In the ETS capture the
                // tool authorizes once (Phase A) and, after the pre-flash basic
                // restart + reconnect (Phase C), issues PID5/memory writes with
                // no re-authorize. A real device with the free-access key granted
                // stays at level 0 until a key is set, so the grant persists
                // across a basic restart within the session.
                Ok(DeviceReaction::default())
            }
            Tpci::Disconnect => {
                self.connected = false;
                Ok(DeviceReaction::default())
            }
            Tpci::Ack(_) => Ok(DeviceReaction::default()),
            Tpci::Nak(_) => Ok(DeviceReaction::default()),
            Tpci::DataUnnumbered => {
                // Unnumbered (broadcast/individual) data carries no L4 sequence.
                let apdu = Apdu::parse(&cemi.tpdu).ok_or(DeviceError::Malformed {
                    service: "APDU".into(),
                    detail: "too short".into(),
                })?;
                self.handle_apdu(cemi, &apdu)
            }
            Tpci::DataConnected(seq) => self.handle_numbered_data(cemi, seq),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::test_support::*;

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
}
