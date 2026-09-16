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

    /// Whether bussard can read this device's tables today.
    ///
    /// Only System B is implemented. System 7 is a known, named gap (issue #49)
    /// rather than an unknown mask; callers that want to distinguish the two use
    /// [`MaskProfile::family`] directly.
    pub fn tables_supported(self) -> bool {
        self.is_system_b()
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
