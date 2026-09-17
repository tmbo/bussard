//! Per-device mask profile: System B vs System 7 behaviour.
//!
//! A simulated device models a specific KNX device generation (mask). System B
//! (mask `0x07B0`) and System 7 (masks `0x0705` / `0x0701`) differ in how the
//! download works: System B is a single relative-segment load-state machine
//! driven over `PID_LOAD_STATE_CONTROL`; System 7 is three parallel,
//! absolute-addressed, memory-mapped load-state machines. This module carries
//! the per-mask facts the [`crate::device::Device`] branches on so a single
//! device implementation can serve either generation strictly.
//!
//! The profile is selected from the product's mask version (`MV-07B0` /
//! `MV-0705` / `MV-0701`) or a `mask:` override in the sim config. The whole
//! design follows `docs/system7-spec.md`; where that spec marks a constant
//! UNKNOWN, the default here is tagged with the greppable `S7-CAL:` marker.

/// How a System 7 device realises its load-state machines on the wire.
///
/// The two variants are the two device-side realisations the spec (section 5)
/// requires the sim to implement, selectable per device so a tool can be
/// conformance-tested against either without a second simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LsmAccess {
    /// Load events are written as a 12-octet record to the LSM control address
    /// via `A_Memory_Write`, and the state is polled at the status address via
    /// `A_Memory_Read`. This is the corpus / first-party default for real 0705
    /// silicon, and thus the default (spec section 5).
    #[default]
    MemoryMapped,
    /// Load events are written to `PID_LOAD_STATE_CONTROL` (PID 5) via
    /// `A_PropertyValue_Write`, and the state is read back via
    /// `A_PropertyValue_Read`. Standards-defensible; built but not the default.
    Property,
}

/// The memory-mapped LSM realisation constants (spec section 5).
///
/// These are all `S7-CAL:` calibration defaults: no public capture confirms the
/// exact control/status addresses or the 12-octet record layout for mask 0705.
/// The M2 live capture settles them; until then the sim uses the best-evidence
/// defaults from `docs/system7-spec.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryMappedLsm {
    /// The address the 12-octet LSM load-event record is written to.
    /// S7-CAL: confirm the LoadControl_M112 control address (0x0104?) against a
    /// live 0705 capture.
    pub control_addr: u16,
    /// The base address the 1-octet LSM status is polled from. Per-LSM status is
    /// at `status_addr + (lsm_index - 1)`.
    /// S7-CAL: confirm the 0xB6EA+ status byte address and per-LSM stride against
    /// a live 0705 capture.
    pub status_addr: u16,
    /// The length of the LSM load-event record written to `control_addr`.
    /// S7-CAL: confirm the 12-octet LoadControl_M112 record length.
    pub record_len: usize,
}

impl Default for MemoryMappedLsm {
    fn default() -> Self {
        // Spec section 5 defaults (all S7-CAL).
        Self {
            control_addr: 0x0104,
            status_addr: 0xB6EA,
            record_len: 12,
        }
    }
}

/// The absolute table-region anchors a System 7 device recognises (spec §2.3).
///
/// These are the fixed 16-bit addresses the LSM index maps to. The download
/// addresses tables and parameters only by absolute memory; there is no
/// `PID_TABLE_REFERENCE` resolution. Per the corpus, every MDT/canonical 0705
/// device uses these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sys7MemoryMap {
    /// LSM 1 table region (address + com-object descriptors). Carries the
    /// per-byte `<Mask>`.
    pub lsm1_table: u16,
    /// LSM 2 table region (association + group-object).
    pub lsm2_table: u16,
    /// LSM 3 parameter image start.
    pub lsm3_params: u16,
}

impl Default for Sys7MemoryMap {
    fn default() -> Self {
        // Corpus-derived canonical anchors (spec §2.3 table).
        Self {
            lsm1_table: 0x4000,
            lsm2_table: 0x4201,
            lsm3_params: 0x4400,
        }
    }
}

/// A System 7 (mask 0705/0701) programming profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sys7Profile {
    /// The exact mask version (0x0705 or 0x0701).
    pub mask: u16,
    /// How the LSMs are realised on the wire.
    pub lsm_access: LsmAccess,
    /// Memory-mapped LSM constants (used when `lsm_access == MemoryMapped`).
    pub mm_lsm: MemoryMappedLsm,
    /// The absolute table-region anchors.
    pub memory_map: Sys7MemoryMap,
    /// The BCU key required for memory access, if the device is keyed. `None`
    /// means free access (the default): any key (or the free-access key
    /// `0xFFFFFFFF`) unlocks. When set, a memory/load write before a successful
    /// `A_Authorize` with the matching key is refused.
    pub bcu_key: Option<u32>,
    /// The 10-octet value object-0 PID 78 (`PID_HARDWARE_TYPE`) reports, matched
    /// by the MDT preflight `CompareProp`. Seeded from the product's application
    /// number by default.
    /// S7-CAL: PID78 value semantics and how the sim seeds it.
    pub hardware_type: [u8; 10],
}

/// The device generation a simulated device models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// System B (mask 0x07B0): single relative-segment LSM over PID 5.
    SystemB {
        /// The mask version reported via `A_DeviceDescriptor_Read` type 0.
        mask: u16,
    },
    /// System 7 (mask 0x0705 / 0x0701): three parallel absolute memory-mapped
    /// LSMs.
    System7(Sys7Profile),
}

impl Profile {
    /// The mask version this device reports via `A_DeviceDescriptor_Read` type 0
    /// (DD0). A real device reports its true mask, so a tool that classifies by
    /// DD0 sees the right generation.
    pub fn mask(&self) -> u16 {
        match self {
            Profile::SystemB { mask } => *mask,
            Profile::System7(p) => p.mask,
        }
    }

    /// True if this is a System 7 profile.
    pub fn is_system7(&self) -> bool {
        matches!(self, Profile::System7(_))
    }

    /// The System 7 sub-profile, if this is a System 7 device.
    pub fn system7(&self) -> Option<&Sys7Profile> {
        match self {
            Profile::System7(p) => Some(p),
            Profile::SystemB { .. } => None,
        }
    }
}

/// Parse a KNX mask version string (`MV-07B0`, `MV-0705`, `0705`, `0x0705`) into
/// its 16-bit mask value. Returns `None` if it is not a recognisable 4-hex-digit
/// mask.
pub fn parse_mask(mask_version: &str) -> Option<u16> {
    let s = mask_version.trim();
    let hex = s
        .strip_prefix("MV-")
        .or_else(|| s.strip_prefix("mv-"))
        .or_else(|| s.strip_prefix("0x"))
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hex.len() != 4 {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

/// The mask family a raw 16-bit mask belongs to (spec section 1).
///
/// Only the two families the sim models are distinguished; every other mask is
/// classified `Other` and the sim refuses to build a device for it (a real
/// simulator would need that generation's model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskFamily {
    /// System B (mask 0x07B0).
    SystemB,
    /// System 7 (mask 0x0705 / 0x0701).
    System7,
    /// An unmodelled family.
    Other,
}

/// Classify a raw mask into its family.
pub fn mask_family(mask: u16) -> MaskFamily {
    match mask {
        0x07B0 => MaskFamily::SystemB,
        0x0705 | 0x0701 => MaskFamily::System7,
        _ => MaskFamily::Other,
    }
}

/// Seed the 10-octet object-0 PID 78 (`PID_HARDWARE_TYPE`) value the MDT
/// preflight `CompareProp` matches, from an application number.
///
/// The corpus MDT preflight compares against `00 00 00 00 03 <marker> 00 00 00 00`
/// where the 6th octet is a hardware-type / app-family marker (app 14 → 0x12,
/// app 8 → 0x11). It is **not** the plain app number across the corpus, so this
/// is a best-effort seed: the low octet of the application number. The caller
/// may override the whole 10-octet value via config when the exact marker is
/// known. Byte 4 is the observed `0x03` run-state marker.
/// S7-CAL: PID78 value semantics and how the sim seeds it.
pub fn default_hardware_type(application_number: u32) -> [u8; 10] {
    let mut v = [0u8; 10];
    v[4] = 0x03;
    v[5] = (application_number & 0xFF) as u8;
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mask_variants() {
        assert_eq!(parse_mask("MV-07B0"), Some(0x07B0));
        assert_eq!(parse_mask("MV-0705"), Some(0x0705));
        assert_eq!(parse_mask("0701"), Some(0x0701));
        assert_eq!(parse_mask("0x07B0"), Some(0x07B0));
        assert_eq!(parse_mask("nonsense"), None);
        assert_eq!(parse_mask("MV-07B"), None);
    }

    #[test]
    fn test_mask_family_classification() {
        assert_eq!(mask_family(0x07B0), MaskFamily::SystemB);
        assert_eq!(mask_family(0x0705), MaskFamily::System7);
        assert_eq!(mask_family(0x0701), MaskFamily::System7);
        assert_eq!(mask_family(0x0012), MaskFamily::Other);
    }

    #[test]
    fn test_default_lsm_access_is_memory_mapped() {
        assert_eq!(LsmAccess::default(), LsmAccess::MemoryMapped);
    }

    #[test]
    fn test_default_mm_lsm_constants() {
        let mm = MemoryMappedLsm::default();
        assert_eq!(mm.control_addr, 0x0104);
        assert_eq!(mm.status_addr, 0xB6EA);
        assert_eq!(mm.record_len, 12);
    }

    #[test]
    fn test_profile_mask_reports_true_mask() {
        let b = Profile::SystemB { mask: 0x07B0 };
        assert_eq!(b.mask(), 0x07B0);
        assert!(!b.is_system7());
        let s7 = Profile::System7(Sys7Profile {
            mask: 0x0705,
            lsm_access: LsmAccess::MemoryMapped,
            mm_lsm: MemoryMappedLsm::default(),
            memory_map: Sys7MemoryMap::default(),
            bcu_key: None,
            hardware_type: default_hardware_type(14),
        });
        assert_eq!(s7.mask(), 0x0705);
        assert!(s7.is_system7());
    }

    #[test]
    fn test_default_hardware_type_layout() {
        let ht = default_hardware_type(8);
        assert_eq!(ht, [0, 0, 0, 0, 0x03, 0x08, 0, 0, 0, 0]);
    }
}
