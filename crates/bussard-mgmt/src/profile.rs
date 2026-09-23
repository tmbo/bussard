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
    /// unparsable (see [`Sys7Profile::corpus_default_for_mask`]).
    ///
    /// Returns `None` for non-System-7 masks. The LSM realisation is
    /// **mask-family-dependent** (not a single global default): the Jung `0705`
    /// family drives load control property-based (PID 5, M2 Jung capture), while
    /// the Theben `0701` family (Meteodata) drives it memory-mapped (11-octet
    /// records to `0x0104`, status at `0xB6EA+`) — established by the real-ETS
    /// download analysis and `[system7-spec §5]`. The data-driven path (issue #49
    /// M1.5) parses `HawkConfigurationData` per mask and overrides these; this is
    /// the named fallback so a download is still attemptable on a device whose
    /// product data lacks the block — the corpus shape is uniform enough within a
    /// family to drive blind `[system7-spec §2.4]`.
    pub fn sys7_default_profile(self) -> Option<Sys7Profile> {
        if self.is_system_7() {
            Some(Sys7Profile::corpus_default_for_mask(self.mask))
        } else {
            None
        }
    }
    /// What bussard can do with a device carrying this mask.
    ///
    /// This is the **single source of truth** for mask support: `plan`, `apply`,
    /// `flash` and `reconstruct` all refuse through it, `bussard audit` renders
    /// it as a column, and [`capability_table`] renders it as the table in
    /// `docs/SAFETY.md` (a test asserts the doc matches this function).
    pub fn capabilities(self) -> MaskCapabilities {
        match self.family {
            MaskFamily::SystemB => MaskCapabilities {
                plan_apply: true,
                flash: true,
                describe: true,
                reconstruct: true,
                note: "tables live in device-allocated segments found via PID_TABLE_REFERENCE; \
                       full read and write support",
            },
            MaskFamily::System7 => MaskCapabilities {
                plan_apply: true,
                flash: true,
                describe: true,
                reconstruct: true,
                note: "memory-mapped tables (default 0x4000 / 0x4201), A_Authorize required; \
                       line-mode `reconstruct --line` records a stub instead of tables",
            },
            MaskFamily::System2 => MaskCapabilities {
                plan_apply: false,
                flash: false,
                describe: true,
                reconstruct: false,
                note: "classified but unsupported; program it with ETS",
            },
            MaskFamily::System1 => MaskCapabilities {
                plan_apply: false,
                flash: false,
                describe: true,
                reconstruct: false,
                note: "classified but unsupported; program it with ETS",
            },
            MaskFamily::Unknown => MaskCapabilities {
                plan_apply: false,
                flash: false,
                describe: true,
                reconstruct: false,
                note: "mask not recognised; program it with ETS",
            },
        }
    }
}

/// What bussard can do with one mask version: the capability row behind every
/// mask refusal and the `docs/SAFETY.md` support table.
///
/// Build one with [`MaskProfile::capabilities`]. `describe` is `true` for every
/// mask because `bussard describe` enumerates interface objects and property
/// descriptions on any device that answers, without a mask gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskCapabilities {
    /// `bussard plan` can read the live link tables and `bussard apply` can
    /// rewrite them.
    pub plan_apply: bool,
    /// `bussard flash` can download an application program.
    pub flash: bool,
    /// `bussard describe` can enumerate the device's interface objects.
    pub describe: bool,
    /// Single-device `bussard reconstruct` can read the live tables back.
    pub reconstruct: bool,
    /// A short human note for the support table; never contains a `|`, so it is
    /// safe to render inside a Markdown table cell.
    pub note: &'static str,
}

impl MaskCapabilities {
    /// A compact "bussard can: ..." summary for a report column.
    ///
    /// Lists the write-capable commands first, then the always-available
    /// `describe`; a mask with no table support renders as `describe only`.
    pub fn summary(self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.plan_apply {
            parts.push("plan/apply");
        }
        if self.flash {
            parts.push("flash");
        }
        if self.reconstruct {
            parts.push("reconstruct");
        }
        if self.describe {
            parts.push("describe");
        }
        if parts.len() == 1 {
            return format!("{} only", parts[0]);
        }
        parts.join(", ")
    }
}

/// Every mask version bussard classifies, in ascending order, with its
/// capabilities.
///
/// This is what `docs/SAFETY.md`'s "Supported device masks" table is rendered
/// from and what `bussard audit` groups devices by. Adding a mask to
/// [`MaskProfile::from_mask`] means adding it here too, or the doc test fails.
pub fn capability_table() -> Vec<(u16, MaskCapabilities)> {
    KNOWN_MASKS
        .iter()
        .map(|&mask| (mask, MaskProfile::from_mask(mask).capabilities()))
        .collect()
}

/// Every mask [`MaskProfile::from_mask`] classifies into a named family, in
/// ascending order.
const KNOWN_MASKS: &[u16] = &[
    0x0010, 0x0011, 0x0012, 0x0013, 0x0020, 0x0021, 0x0025, 0x0300, 0x0310, 0x0311, 0x0700, 0x0701,
    0x0705, 0x07B0, 0x27B0, 0x57B0,
];

/// How a System 7 device realises its load-state machines (the single most
/// load-bearing System 7 design decision — `[system7-spec §5]`).
///
/// The realisation is **vendor / mask-family dependent**, not a single global
/// default. Two real-ETS download captures settle it:
/// - **Jung `0705`** (M2, issue #70; and the binaereingang / automitschalter /
///   schaltaktor 0705 analysis captures) drives load control **property-based**
///   (PID 5), so [`LsmRealisation::Property`] is the `0705` default.
/// - **Theben `0701`** (Meteodata 1409207, IA 1.1.202) drives load control
///   **memory-mapped**: 11-octet records written by `A_Memory_Write` to `0x0104`,
///   status read at `0xB6EA + (lsm - 1)`, with zero PID-5 traffic. So
///   [`LsmRealisation::MemoryMapped`] is the `0701` default.
///
/// Select per mask via [`Sys7Profile::corpus_default_for_mask`] (the fallback) or
/// from `HawkConfigurationData` when the product carries a usable block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmRealisation {
    /// **Memory-mapped**: an 11-octet LSM-control record written by `A_Memory_Write`
    /// to a control address (default `0x0104`), with status polled by
    /// `A_Memory_Read` at a status address (default `0xB6EA + (lsm - 1)`)
    /// `[system7-spec §5]`. This is the confirmed default for the Theben `0701`
    /// family (Meteodata capture: 11-octet writes to `0x0104`, `MemoryRead @0xB6EC`
    /// returning `02`…`01`, zero PID-5 traffic). It is the alternative — not the
    /// default — for the Jung `0705` family, whose M2 capture is property-based (no
    /// write to `0x0104`; the only `0xB6EA+` touch is a single readable-status
    /// read).
    MemoryMapped {
        /// The LSM-control write address (default `0x0104`).
        control_addr: u16,
        /// The LSM status-poll base address (default `0xB6EA`); the status of LSM
        /// `n` is read at `status_addr + (n - 1)`.
        status_addr: u16,
    },
    /// **Property-based** (the Jung `0705` default, M2 capture): load events
    /// written to `PID_LOAD_STATE_CONTROL` (PID 5) via `A_PropertyValue_Write`
    /// (10-octet load event, one element at index 1), state read back via
    /// `A_PropertyValue_Read`. The M2 capture shows exactly this: every load
    /// control on objects 1/2/3 is an `A_PropertyValue_Write(objN, PID 5)`
    /// `[system7-spec §5, M2 Jung 0705 capture CONFIRMED]`.
    Property,
}

/// The default memory-mapped LSM control-write address for the Theben `0701`
/// family (`[system7-spec §5]`; Meteodata capture: 11-octet writes to `0x0104`).
pub const SYS7_DEFAULT_CONTROL_ADDR: u16 = 0x0104;
/// The default memory-mapped LSM status-poll base address for the Theben `0701`
/// family; the status of LSM `n` is read at this address `+ (n - 1)`
/// (`[system7-spec §5]`; Meteodata capture: `MemoryRead @0xB6EC` for LSM 3).
pub const SYS7_DEFAULT_STATUS_ADDR: u16 = 0xB6EA;

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
    /// The mask's Hawk `VerifyMode` feature, or `None` when the mask declares
    /// none (Theben `0700`/`0701`). With a verify mode (Jung `0705` declares `1`)
    /// ETS writes each segment whole and relies on the device's verification;
    /// without one it reads each chunk back first, writes only the chunks that
    /// differ, and the read-back is the verification (issue #133). See
    /// [`Sys7Profile::read_compare_write`].
    pub verify_mode: Option<u8>,
}

impl Sys7Profile {
    /// The mask-family-aware default System 7 profile (`[system7-spec §2.4/§5]`):
    /// authorize level 0 (free-access key), EEPROM mem-type 3 for the table/param
    /// regions, RAM mem-type 2 for the low-RAM allocations, and an LSM realisation
    /// selected by mask family:
    ///
    /// - Jung `0705` (and any other non-`0701` System 7 mask) →
    ///   [`LsmRealisation::Property`] (PID 5), confirmed by the M2 Jung capture
    ///   (issue #70) and the 0705 analysis captures.
    /// - Theben `0701` → [`LsmRealisation::MemoryMapped`] at the default
    ///   control/status addresses ([`SYS7_DEFAULT_CONTROL_ADDR`] /
    ///   [`SYS7_DEFAULT_STATUS_ADDR`]), confirmed by the Meteodata 0701 capture.
    ///
    /// This is the fallback when no `HawkConfigurationData` selects a realisation;
    /// a product-data Hawk block still overrides `lsm` via
    /// [`sys7_profile_from_hawk`](../download/index.html).
    pub fn corpus_default_for_mask(mask: u16) -> Sys7Profile {
        // The 0701 family (Theben Meteodata) is memory-mapped; every other System 7
        // mask (Jung 0705) defaults to property-based load control.
        let lsm = if mask & 0x0FFF == 0x701 {
            LsmRealisation::MemoryMapped {
                control_addr: SYS7_DEFAULT_CONTROL_ADDR,
                status_addr: SYS7_DEFAULT_STATUS_ADDR,
            }
        } else {
            LsmRealisation::Property
        };
        // The `knx_master.xml` Hawk blocks: MV-0705 declares `VerifyMode=1`,
        // MV-0700 and MV-0701 declare none (issue #133).
        let verify_mode = match mask & 0x0FFF {
            0x700 | 0x701 => None,
            _ => Some(1),
        };
        Sys7Profile {
            lsm,
            authorize_level: 0,
            eeprom_mem_type: 3,
            ram_mem_type: 2,
            verify_mode,
        }
    }

    /// Whether segment images are streamed read-compare-write: read each chunk
    /// first, write only the chunks that differ from the image, and count the
    /// read-back as the verification. True when the mask declares no
    /// `VerifyMode` (the ETS behaviour on the Theben `0701` Meteodata capture,
    /// issue #133); a `VerifyMode` mask is written blind.
    pub fn read_compare_write(&self) -> bool {
        self.verify_mode.is_none()
    }

    /// The property-based System 7 default profile (Jung `0705`): a convenience
    /// for callers that already know the mask is the property family, and the
    /// value [`corpus_default_for_mask`](Sys7Profile::corpus_default_for_mask)
    /// returns for every non-`0701` System 7 mask. Equivalent to
    /// `corpus_default_for_mask(0x0705)`.
    pub fn corpus_default() -> Sys7Profile {
        Sys7Profile::corpus_default_for_mask(0x0705)
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
    fn test_corpus_default_for_mask_verify_mode_matches_hawk() {
        // knx_master.xml: MV-0705 declares VerifyMode=1 (blind write), MV-0700 and
        // MV-0701 declare none (read-compare-write, issue #133).
        let jung = Sys7Profile::corpus_default_for_mask(0x0705);
        assert_eq!(jung.verify_mode, Some(1));
        assert!(!jung.read_compare_write());
        for mask in [0x0700u16, 0x0701] {
            let p = Sys7Profile::corpus_default_for_mask(mask);
            assert_eq!(p.verify_mode, None, "{mask:04X}");
            assert!(p.read_compare_write(), "{mask:04X}");
        }
    }

    #[test]
    fn test_sys7_default_profile_is_mask_family_aware() {
        // The realisation is vendor/mask-family dependent, NOT a single global
        // default. Jung 0705 (M2 capture) drives PID 5 (property); Theben 0701
        // (Meteodata capture) drives memory-mapped 11-octet records to 0x0104 with
        // status at 0xB6EA+. The common mem-types/authorize level are shared.
        for mask in [0x0705u16, 0x0700] {
            let p = MaskProfile::from_mask(mask);
            assert!(p.is_system_7(), "{mask:04X}");
            assert_eq!(p.max_apdu_fallback(), 15, "{mask:04X}");
            let s7 = p.sys7_default_profile().expect("a System 7 profile");
            assert_eq!(
                s7.lsm,
                LsmRealisation::Property,
                "{mask:04X} is the property family"
            );
            assert_eq!(s7.authorize_level, 0, "{mask:04X}");
            assert_eq!(s7.eeprom_mem_type, 3, "{mask:04X}");
            assert_eq!(s7.ram_mem_type, 2, "{mask:04X}");
        }

        // Theben 0701 (Meteodata) is memory-mapped at the default control/status
        // addresses — this is the regression the M2 "Property for all System 7"
        // default caused, now fixed.
        let theben = MaskProfile::from_mask(0x0701);
        assert!(theben.is_system_7());
        let s7 = theben.sys7_default_profile().expect("a System 7 profile");
        assert_eq!(
            s7.lsm,
            LsmRealisation::MemoryMapped {
                control_addr: SYS7_DEFAULT_CONTROL_ADDR,
                status_addr: SYS7_DEFAULT_STATUS_ADDR,
            },
            "Theben 0701 Meteodata drives load control memory-mapped"
        );
        assert_eq!(s7.authorize_level, 0);
        assert_eq!(s7.eeprom_mem_type, 3);
        assert_eq!(s7.ram_mem_type, 2);
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
    fn test_capabilities_match_the_families() {
        for mask in [0x07B0u16, 0x27B0, 0x57B0] {
            let caps = MaskProfile::from_mask(mask).capabilities();
            assert!(caps.plan_apply && caps.flash && caps.describe && caps.reconstruct);
        }
        for mask in [0x0700u16, 0x0701, 0x0705] {
            let caps = MaskProfile::from_mask(mask).capabilities();
            assert!(caps.plan_apply && caps.flash && caps.describe && caps.reconstruct);
        }
        for mask in [0x0012u16, 0x0021, 0x0300, 0x1234] {
            let caps = MaskProfile::from_mask(mask).capabilities();
            assert!(!caps.plan_apply, "{mask:04X}");
            assert!(!caps.flash, "{mask:04X}");
            assert!(!caps.reconstruct, "{mask:04X}");
            // `describe` is never mask-gated.
            assert!(caps.describe, "{mask:04X}");
            assert_eq!(caps.summary(), "describe only", "{mask:04X}");
        }
    }

    #[test]
    fn test_capability_table_covers_every_known_mask() {
        let table = capability_table();
        // Every row classifies into a named family (no Unknown leaked in), and
        // the masks are unique and ascending.
        let mut previous = None;
        for (mask, caps) in &table {
            let profile = MaskProfile::from_mask(*mask);
            assert_ne!(
                profile.family(),
                MaskFamily::Unknown,
                "{mask:04X} is in the table but classifies as Unknown"
            );
            assert_eq!(*caps, profile.capabilities(), "{mask:04X}");
            assert!(!caps.note.contains('|'), "{mask:04X} note breaks Markdown");
            if let Some(prev) = previous {
                assert!(
                    prev < *mask,
                    "the table must ascend ({prev:04X} >= {mask:04X})"
                );
            }
            previous = Some(*mask);
        }
        // The three supported System B media and the three System 7 masks are
        // present; a regression that dropped one would silently shrink the doc.
        for mask in [0x07B0u16, 0x27B0, 0x57B0, 0x0700, 0x0701, 0x0705] {
            assert!(
                table.iter().any(|(m, _)| *m == mask),
                "{mask:04X} missing from the capability table"
            );
        }
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
