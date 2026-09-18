//! Mask-version classification: one seam for KNX mask-version-specific behaviour.
//!
//! A KNX device reports a 16-bit **mask version** via `A_DeviceDescriptor_Read`
//! (type 0). Two facts are packed into it:
//!
//! - the **medium** in the high nibble (`0x0…` = TP1, `0x2…` = RF, `0x5…` =
//!   KNX-IP), and
//! - the **system generation** in the low 12 bits (`x7B0` = System B, `x705` /
//!   `x701` = System 7, `x3xx` = System 2, `x0xx` = System 1 / BCU1).
//!
//! Historically bussard branched on this ad hoc — `is_system_b(mask)`, exact
//! `== 0x07B0` compares, and `match mask { … }` scattered across the mgmt,
//! download and CLI crates. [`MaskProfile`] pulls every one of those facts
//! behind a single value so that:
//!
//! - the medium-agnostic System B stack applies uniformly to `07B0`, `57B0` and
//!   `27B0` (a KNX-IP device is not refused just because it is not TP1), and
//! - System 7 write support (issue #49) can slot behind [`MaskFamily::System7`]
//!   without adding new `if` ladders — the branch points already exist here.
//!
//! This module is **classification only**: it reads a mask and answers questions
//! about it. It performs no bus I/O and has no dependencies beyond the mask word.

/// The transport medium a mask version's high nibble encodes.
///
/// The medium is orthogonal to the system generation: a System B device exists
/// on TP1 (`07B0`), RF (`27B0`) and KNX-IP (`57B0`) alike. Callers that care
/// only about the management stack should prefer [`MaskProfile::family`] and
/// ignore the medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnxMedium {
    /// Twisted-pair 1 (the classic `0x0…` bus). The default and most common.
    TwistedPair,
    /// Radio frequency (`0x2…`).
    RadioFrequency,
    /// KNX-IP (`0x5…`) — a native IP device, not a tunnelling gateway.
    KnxIp,
    /// A high nibble bussard does not recognise.
    Unknown,
}

impl KnxMedium {
    /// Classifies the medium from a mask version's high nibble.
    fn from_mask(mask: u16) -> Self {
        match mask >> 12 {
            0x0 => KnxMedium::TwistedPair,
            0x2 => KnxMedium::RadioFrequency,
            0x5 => KnxMedium::KnxIp,
            _ => KnxMedium::Unknown,
        }
    }

    /// A short human label for the medium.
    pub fn label(self) -> &'static str {
        match self {
            KnxMedium::TwistedPair => "TP1",
            KnxMedium::RadioFrequency => "RF",
            KnxMedium::KnxIp => "KNX-IP",
            KnxMedium::Unknown => "unknown medium",
        }
    }
}

/// The KNX system generation (management-stack family) a mask version selects.
///
/// This is the medium-independent classification bussard's read/write paths
/// branch on. The low 12 bits of the mask decide the family; the high nibble
/// (the medium) is stripped first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskFamily {
    /// System B (`x7B0`): interface-object properties and loadable tables. The
    /// only family bussard can read and write today.
    SystemB,
    /// System 7 (`x705` / `x701` / `x700`): memory-mapped tables that require
    /// `A_Authorize` before access. Read/write support is issue #49; today
    /// bussard classifies these but does not drive them.
    System7,
    /// System 2 (`x3xx`): the BCU2 generation. Classified but unsupported.
    System2,
    /// System 1 / BCU1 family (`x0xx`, plus the `x02x` realisation type some IP
    /// interfaces report — issue #30). Classified but unsupported.
    System1,
    /// A mask bussard does not recognise.
    Unknown,
}

impl MaskFamily {
    /// A human-readable name for the family, matching the historical
    /// [`system_type`](crate::system_type) strings.
    pub fn label(self) -> &'static str {
        match self {
            MaskFamily::SystemB => "System B",
            MaskFamily::System7 => "System 7",
            MaskFamily::System2 => "System 2",
            MaskFamily::System1 => "System 1",
            MaskFamily::Unknown => "System ?",
        }
    }
}

/// A classified device mask version: the single seam for mask-dependent
/// behaviour.
///
/// Build one with [`MaskProfile::from_mask`], then ask it the questions the code
/// used to answer with scattered bit tests:
///
/// ```
/// use bussard_mgmt::profile::{MaskProfile, MaskFamily, KnxMedium};
///
/// // System B over KNX-IP: same management stack as TP1, different medium.
/// let p = MaskProfile::from_mask(0x57B0);
/// assert_eq!(p.family(), MaskFamily::SystemB);
/// assert_eq!(p.medium(), KnxMedium::KnxIp);
/// assert!(p.is_system_b());
/// assert!(!p.requires_authorize());
///
/// // System 7 is memory-mapped and needs A_Authorize (issue #49).
/// let p = MaskProfile::from_mask(0x0705);
/// assert_eq!(p.family(), MaskFamily::System7);
/// assert!(p.uses_memory_mapped_tables());
/// assert!(p.requires_authorize());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskProfile {
    mask: u16,
    family: MaskFamily,
    medium: KnxMedium,
}

impl MaskProfile {
    /// Classifies a raw mask version into a profile.
    ///
    /// The low 12 bits select the [`MaskFamily`]; the high nibble the
    /// [`KnxMedium`]. Both are derived independently so the medium-agnostic
    /// System B family covers `07B0` / `57B0` / `27B0` uniformly.
    pub fn from_mask(mask: u16) -> Self {
        let family = match mask & 0x0FFF {
            0x7B0 => MaskFamily::SystemB,
            0x705 | 0x701 | 0x700 => MaskFamily::System7,
            0x300 | 0x310 | 0x311 => MaskFamily::System2,
            // System 1 / BCU1: the classic 0x001x masks plus the 0x002x
            // realisation type some BCU1-based IP interfaces report (issue #30).
            0x010..=0x013 | 0x020 | 0x021 | 0x025 => MaskFamily::System1,
            _ => MaskFamily::Unknown,
        };
        MaskProfile {
            mask,
            family,
            medium: KnxMedium::from_mask(mask),
        }
    }

    /// The raw mask version this profile was built from.
    pub fn mask(self) -> u16 {
        self.mask
    }

    /// The system generation / management-stack family.
    pub fn family(self) -> MaskFamily {
        self.family
    }

    /// The transport medium (from the mask's high nibble).
    pub fn medium(self) -> KnxMedium {
        self.medium
    }

    /// A human-readable system-type label (`"System B"`, `"System 7"`, …),
    /// matching the legacy [`system_type`](crate::system_type) output.
    pub fn system_type(self) -> &'static str {
        self.family.label()
    }

    /// Whether this mask belongs to the System B family (`x7B0`).
    ///
    /// This is the classification bussard's supported read/write paths gate on.
    /// It is deliberately medium-agnostic: `07B0` (TP1), `57B0` (KNX-IP) and
    /// `27B0` (RF) all answer `true`, because the interface-object and
    /// loadable-table stack is shared across the whole System B profile
    /// (KNX standard 3/5/1). This is the replacement for the free
    /// [`is_system_b`](crate::is_system_b) function.
    pub fn is_system_b(self) -> bool {
        self.family == MaskFamily::SystemB
    }

    /// Whether loadable tables are served from **memory** rather than as
    /// interface-object property arrays.
    ///
    /// System B exposes group-address / association tables through
    /// `A_PropertyValue_Read` (with a `PID_TABLE_REFERENCE` + `A_Memory_Read`
    /// fallback). System 7 keeps its tables purely memory-mapped, which is the
    /// core of the issue #49 work. Extension point: the System 7 table reader
    /// will branch on this.
    pub fn uses_memory_mapped_tables(self) -> bool {
        self.family == MaskFamily::System7
    }

    /// Whether the device requires `A_Authorize` before its tables can be
    /// accessed.
    ///
    /// System 7 gates memory access behind an authorisation key; System B does
    /// not (bussard opens System B sessions unauthenticated, attempting a
    /// best-effort free-access authorize only where a device happens to want
    /// it). Extension point for issue #49: the write path will present a key
    /// when this is `true`.
    pub fn requires_authorize(self) -> bool {
        self.family == MaskFamily::System7
    }

    /// Whether this mask belongs to the System 7 family (`x705` / `x701` /
    /// `x700`) — the memory-mapped, absolute-addressed download path (issue #49).
    pub fn is_system_7(self) -> bool {
        self.family == MaskFamily::System7
    }

    /// Whether bussard can read this device's tables today.
    ///
    /// Only System B is implemented. System 7 is a known, named gap (issue #49)
    /// rather than an unknown mask; callers that want to distinguish the two use
    /// [`MaskProfile::family`] directly.
    pub fn tables_supported(self) -> bool {
        self.is_system_b()
    }

    /// The conservative fallback max-APDU (NPDU octet count) for this family when
    /// the device does not advertise `PID_MAX_APDU_LENGTH`.
    ///
    /// System 7 has no extended-frame guarantee: it is standard-frame only, so
    /// the floor is **15** (→ 12 data octets per `A_Memory_Write`/`_Read` via
    /// [`crate::apci::memory_chunk_for_apdu`], i.e.
    /// [`crate::apci::CONSERVATIVE_MEMORY_CHUNK`]) `[system7-spec §6, XKNX
    /// PR#1834/#1938]`. System B shares the same 15-octet standard-frame floor;
    /// it scales up only when a device advertises a larger APDU.
    pub fn max_apdu_fallback(self) -> u16 {
        // Both families floor at the standard-frame ceiling (NPDU length 15).
        // System 7 must NEVER be pushed to an extended frame it may reject.
        15
    }

    /// The default System 7 programming profile for this mask: the corpus-derived
    /// defaults used when a `.knxprod`'s `HawkConfigurationData` is absent or
    /// unparsable (see [`Sys7Profile::corpus_default`]).
    ///
    /// Returns `None` for non-System-7 masks. The data-driven path (issue #49
    /// M1.5) parses `HawkConfigurationData` per mask and overrides these; this is
    /// the named fallback so a download is still attemptable on a device whose
    /// product data lacks the block — the corpus shape is uniform enough to drive
    /// blind `[system7-spec §2.4]`.
    pub fn sys7_default_profile(self) -> Option<Sys7Profile> {
        if self.is_system_7() {
            Some(Sys7Profile::corpus_default())
        } else {
            None
        }
    }
}

/// How a System 7 device realises its load-state machines (the single most
/// load-bearing System 7 design decision — `[system7-spec §5]`).
///
/// The two research inputs disagree on this point, so bussard implements a seam
/// with two variants and a best-evidence default ([`LsmRealisation::MemoryMapped`]).
/// Selected per mask from `HawkConfigurationData` when present; falls back to the
/// memory-mapped default otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmRealisation {
    /// **Memory-mapped** (the default): a 12-octet LSM-control record written by
    /// `A_Memory_Write` to a control address (default `0x0104`), with status
    /// polled by `A_Memory_Read` at a status address (default `0xB6EA`). This is
    /// what both the corpus and the first-party BIM-M112 evidence show for the
    /// real 0705 devices bussard must flash `[system7-spec §5]`.
    MemoryMapped {
        /// The LSM-control write address (default `0x0104`). `S7-CAL: confirm the
        /// LSM control address against a live 0705 capture`.
        control_addr: u16,
        /// The LSM status-poll base address (default `0xB6EA`); the status of LSM
        /// `n` is read relative to this. `S7-CAL: confirm the 0xB6EA+ status
        /// address and its per-LSM stride`.
        status_addr: u16,
    },
    /// **Property-based**: load events written to `PID_LOAD_STATE_CONTROL` (PID 5)
    /// via `A_PropertyValue_Write`, state read back via `A_PropertyValue_Read`.
    /// Standards-defensible (the BCU2 / System B lineage) but not the default; it
    /// exists so that if a capture proves a given 0705 silicon is property-based,
    /// flipping the profile bit is a one-line change `[system7-spec §5]`.
    Property,
}

/// The per-mask System 7 programming configuration: the resource/LSM realisation,
/// table locations and authorize level a System 7 download needs.
///
/// This is the data-driven mask profile issue #49 calls for: parsed from a
/// `.knxprod`'s `HawkConfigurationData` at import time (see `bussard-ets`), or
/// filled from [`Sys7Profile::corpus_default`] when that block is absent. Do NOT
/// hardcode per-mask addresses at call sites — resolve them through this value
/// `[system7-spec §2.4]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sys7Profile {
    /// How the load-state machines are driven (memory-mapped vs property).
    pub lsm: LsmRealisation,
    /// The access level to authorize with before memory access. `0` = highest
    /// privilege; the free-access key grants a usable level on an unkeyed device.
    pub authorize_level: u8,
    /// The default memory type for absolute-segment allocation of the EEPROM
    /// table/param regions (`0x4000`/`0x4201`/`0x4400`). `3` = EEPROM
    /// `[system7-spec §4.1/§4.2]`.
    pub eeprom_mem_type: u8,
    /// The default memory type for the low-RAM working-region allocations
    /// (`0x0700`/`0x0730`). `2` = RAM `[system7-spec §4.2]`.
    pub ram_mem_type: u8,
}

impl Sys7Profile {
    /// The corpus-derived default System 7 profile (`[system7-spec §2.4/§5]`):
    /// memory-mapped LSM at `0x0104` / `0xB6EA`, authorize level 0 (free-access
    /// key), EEPROM mem-type 3 for the table/param regions and RAM mem-type 2 for
    /// the low-RAM allocations.
    ///
    /// `S7-CAL: every constant here is a best-evidence default from the corpus and
    /// first-party BIM-M112 evidence; a live Jung 0705 capture (issue #49 M2) must
    /// confirm the LSM control/status addresses, the record layout and the
    /// authorize requirement.`
    pub fn corpus_default() -> Sys7Profile {
        Sys7Profile {
            lsm: LsmRealisation::MemoryMapped {
                control_addr: 0x0104,
                status_addr: 0xB6EA,
            },
            authorize_level: 0,
            eeprom_mem_type: 3,
            ram_mem_type: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_mask_classifies_system_b_all_media() {
        for (mask, medium) in [
            (0x07B0u16, KnxMedium::TwistedPair),
            (0x57B0, KnxMedium::KnxIp),
            (0x27B0, KnxMedium::RadioFrequency),
        ] {
            let p = MaskProfile::from_mask(mask);
            assert_eq!(p.family(), MaskFamily::SystemB, "{mask:04X}");
            assert_eq!(p.medium(), medium, "{mask:04X}");
            assert!(p.is_system_b(), "{mask:04X}");
            assert!(p.tables_supported(), "{mask:04X}");
            assert!(!p.uses_memory_mapped_tables(), "{mask:04X}");
            assert!(!p.requires_authorize(), "{mask:04X}");
        }
    }

    #[test]
    fn test_from_mask_classifies_system_7() {
        for mask in [0x0705u16, 0x0701, 0x0700] {
            let p = MaskProfile::from_mask(mask);
            assert_eq!(p.family(), MaskFamily::System7, "{mask:04X}");
            assert!(!p.is_system_b(), "{mask:04X}");
            assert!(!p.tables_supported(), "{mask:04X}");
            assert!(p.uses_memory_mapped_tables(), "{mask:04X}");
            assert!(p.requires_authorize(), "{mask:04X}");
        }
    }

    #[test]
    fn test_sys7_default_profile_is_memory_mapped_corpus_default() {
        for mask in [0x0705u16, 0x0701, 0x0700] {
            let p = MaskProfile::from_mask(mask);
            assert!(p.is_system_7(), "{mask:04X}");
            assert_eq!(p.max_apdu_fallback(), 15, "{mask:04X}");
            let s7 = p.sys7_default_profile().expect("a System 7 profile");
            assert_eq!(
                s7.lsm,
                LsmRealisation::MemoryMapped {
                    control_addr: 0x0104,
                    status_addr: 0xB6EA,
                },
                "{mask:04X}"
            );
            assert_eq!(s7.authorize_level, 0, "{mask:04X}");
            assert_eq!(s7.eeprom_mem_type, 3, "{mask:04X}");
            assert_eq!(s7.ram_mem_type, 2, "{mask:04X}");
        }
    }

    #[test]
    fn test_sys7_default_profile_absent_for_non_system_7() {
        assert!(
            MaskProfile::from_mask(0x07B0)
                .sys7_default_profile()
                .is_none()
        );
        assert!(!MaskProfile::from_mask(0x07B0).is_system_7());
        // System B also floors at the standard-frame ceiling (15).
        assert_eq!(MaskProfile::from_mask(0x07B0).max_apdu_fallback(), 15);
    }

    #[test]
    fn test_from_mask_classifies_legacy_and_unknown() {
        assert_eq!(MaskProfile::from_mask(0x0012).family(), MaskFamily::System1);
        // BCU1-family realisation type reported by a Jung IP interface (#30).
        assert_eq!(MaskProfile::from_mask(0x0021).family(), MaskFamily::System1);
        assert_eq!(MaskProfile::from_mask(0x0020).family(), MaskFamily::System1);
        assert_eq!(MaskProfile::from_mask(0x0025).family(), MaskFamily::System1);
        assert_eq!(MaskProfile::from_mask(0x0300).family(), MaskFamily::System2);
        assert_eq!(MaskProfile::from_mask(0x1234).family(), MaskFamily::Unknown);
    }

    #[test]
    fn test_system_type_matches_legacy_labels() {
        assert_eq!(MaskProfile::from_mask(0x07B0).system_type(), "System B");
        assert_eq!(MaskProfile::from_mask(0x0705).system_type(), "System 7");
        assert_eq!(MaskProfile::from_mask(0x0012).system_type(), "System 1");
        assert_eq!(MaskProfile::from_mask(0x0300).system_type(), "System 2");
        assert_eq!(MaskProfile::from_mask(0x1234).system_type(), "System ?");
    }
}
