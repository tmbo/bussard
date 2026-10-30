//! One streaming parser for a manufacturer ApplicationProgram XML file.
//!
//! These files reach 28 MB, so we never build a DOM: `quick-xml` pulls events
//! and we accumulate typed records. This is the superset both consumers need:
//!
//! * `.knxprod` reading (`bussard-prod`) needs identity, the com-object table,
//!   parameter types, parameters and their refs, code segments (metadata only)
//!   and the load procedure.
//! * `.knxproj` import (`bussard-project`) additionally needs the Dynamic
//!   section's `<Channel>` definitions and module `<Argument>` ids, plus the
//!   base com-object `BaseNumber` reference used for module object numbering.
//!
//! Everything is keyed by full XML `Id`, so refs resolve by lookup. The
//! translations of one language from the file's `<Languages>` section
//! override the default-language `Name`, `Text` and `FunctionText`
//! attributes, matching ETS behaviour: en-US for [`parse_application_program`],
//! the caller's choice for [`parse_application_program_in`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::attrs::{Attrs, flagset_from, get};
use crate::dpt::parse_ets_dpt;
use crate::error::{EtsError, Result};
use crate::flags::FlagSet;
use crate::translation::TranslationCollector;
use bussard_model::Dpt;
pub use bussard_model::color_codec::ColorSpace;
pub use bussard_model::dynamic::{
    Allocator, BlockRef, ChannelRef, CompareOp, ComputedArg, DynamicNode, DynamicWhen, EnumValue,
    LabelMatch, Memory, Union, UnionMember, WhenTest, enum_member_by_label, flatten_containers,
};

/// A base `<ComObject>` from the application program.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ComObject {
    /// The full XML `Id`.
    pub id: String,
    /// The com-object number (the stable, user-visible handle).
    pub number: u16,
    /// Object `Name`.
    pub name: Option<String>,
    /// Object `Text`.
    pub text: Option<String>,
    /// `FunctionText`.
    pub function_text: Option<String>,
    /// Declared `ObjectSize`, e.g. `"1 Bit"`.
    pub object_size: Option<String>,
    /// Effective DPT declared on the base object, if any.
    pub dpt: Option<Dpt>,
    /// Flags declared on the base object.
    pub flags: FlagSet,
    /// The declared `Priority`, if any (absent means Low).
    #[serde(default)]
    pub priority: Option<bussard_model::Priority>,
    /// For a module com-object: the argument id (its `BaseNumber` attribute)
    /// whose value is added to `number` to compute the instance's effective
    /// object number.
    pub base_number_ref: Option<String>,
}

/// A `<ComObjectRef>` from the application program.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ComObjectRef {
    /// The full XML `Id`.
    pub id: String,
    /// The base `<ComObject>` id this ref points at (its `RefId`).
    pub ref_id: String,
    /// Optional `Name` override.
    pub name: Option<String>,
    /// Optional `Text` override.
    pub text: Option<String>,
    /// Optional `FunctionText` override.
    pub function_text: Option<String>,
    /// Optional `ObjectSize` override.
    pub object_size: Option<String>,
    /// Optional DPT override.
    pub dpt: Option<Dpt>,
    /// Flags declared on the ref (override the base's).
    pub flags: FlagSet,
    /// Optional `Priority` override.
    #[serde(default)]
    pub priority: Option<bussard_model::Priority>,
    /// The `TextParameterRefId`, app-relative (e.g. `MD-1_P-1_R-1`): the
    /// parameter ref whose value replaces the `{{0}}`/`{{0:…}}` placeholder in
    /// [`Self::text`] (see [`crate::label::substitute_label`]).
    pub text_parameter_ref: Option<String>,
}

/// A `<Channel>` definition from the application program's Dynamic section.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ChannelDef {
    /// Channel `Name` (the manufacturer's short label, e.g. `"Relaisausgänge"`).
    pub name: Option<String>,
    /// Channel `Text` (the human label, often carrying `{{Arg…}}` placeholders,
    /// e.g. `"{{ArgBeschriftungRelais}} {{ArgBeschriftung}} ({{0:...}})"`).
    pub text: Option<String>,
}

/// One `<Module>` instantiation from the Dynamic section: a set of the module
/// definition's argument values.
///
/// A module-based application defines its com-objects and parameters once (in a
/// `<ModuleDef>`), then instantiates them once per channel with a `<Module>`
/// element carrying `<NumericArg RefId=… Value=…>` children. Each `RefId` is a
/// module `<Argument>` id (e.g. `MD-1_A-2` = `argObj`, the com-object base
/// number; `MD-1_A-3` = `argPar`, the parameter memory base offset). A
/// com-object's effective ASAP is `base.number + arg_values[base_number_ref]`,
/// and a module parameter's effective byte offset is
/// `declared_offset + arg_values[base_offset]`.
///
/// The argument values are keyed by the **app-relative argument id** (with the
/// program-id prefix stripped, e.g. `MD-1_A-2`), the same key
/// [`ComObject::base_number_ref`] and [`Memory::base_offset`] carry.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ModuleInstance {
    /// The module instance id (its `Id`, app-relative, e.g. `MD-1_M-3`). A
    /// project's module-instance selector is this id plus `_MI-<n>`.
    pub id: String,
    /// The module definition id this instance instantiates (its `RefId`,
    /// app-relative, e.g. `MD-1`).
    pub module_def: String,
    /// The instance's `<NumericArg>` values, keyed by app-relative argument id.
    pub arg_values: HashMap<String, i64>,
}

/// One channel `<ParameterBlock>`'s com-object membership, captured from the
/// module definition's Dynamic section.
///
/// A module template has a single channel/parameter-block that lists which of
/// the module's com-object refs are instantiated on every channel, plus
/// conditional groups (`<choose ParamRefId><when test>`) whose members appear
/// only when the named parameter takes the `when` value. The captured ids are
/// **com-object-ref ids** (a `ComObjectRefRef`'s `RefId`), which resolve to a
/// [`ComObjectRef`] and thence its base [`ComObject`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ChannelMembership {
    /// Com-object-ref ids always present on every channel (the unconditional
    /// `<ComObjectRefRef>`s directly under the parameter block).
    pub unconditional: Vec<String>,
    /// Conditional groups: a group is included on a channel only when the
    /// parameter it names (`param_ref_id`, a `ParameterRef` id) takes the
    /// group's `when` value.
    pub conditional: Vec<ConditionalGroup>,
    /// Parameter-ref ids referenced by this channel's parameter block
    /// (`<ParameterRefRef>`). A module parameter whose ref is not listed here is
    /// present in the module definition but not shown/written on the channel
    /// (e.g. a `color` parameter with a `<Memory>` that ETS never writes because
    /// no channel references it).
    pub parameter_refs: Vec<String>,
}

/// One `<when>` branch of a `<choose>`: its condition and the com-object-ref ids
/// it contributes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WhenBranch {
    /// The branch condition.
    pub test: WhenTest,
    /// The com-object-ref ids collected directly inside this branch.
    pub members: Vec<String>,
}

/// One `<choose>/<when>` conditional group inside a [`ChannelMembership`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ConditionalGroup {
    /// The `ParameterRef` id (`ParamRefId`) whose value selects a `when` branch.
    pub param_ref_id: String,
    /// The exact-value branches, as `(when-value, com-object-ref ids)` pairs: the
    /// branch whose value equals the parameter's effective value contributes its
    /// members. A `test="0 2"` contributes one pair per listed value.
    ///
    /// This is the flattened view of the exact-match subset of [`Self::branches_all`],
    /// kept because it is what the flash path selects on. Prefer
    /// [`Self::members_for`], which also honours comparison and `default`
    /// branches.
    pub branches: Vec<(i64, Vec<String>)>,
    /// Every branch in document order with its full condition — comparisons and
    /// the `default` branch included.
    pub branches_all: Vec<WhenBranch>,
}

impl ConditionalGroup {
    /// The com-object-ref ids this group contributes when its parameter takes
    /// `value`.
    ///
    /// ETS semantics: the first `<when>` whose test matches wins; if none
    /// matches, the `<when default>` branch (if any) does.
    pub fn members_for(&self, value: i64) -> &[String] {
        if let Some(b) = self.branches_all.iter().find(|b| b.test.matches(value)) {
            return &b.members;
        }
        match self
            .branches_all
            .iter()
            .find(|b| b.test == WhenTest::Default)
        {
            Some(b) => &b.members,
            None => &[],
        }
    }
}

/// A resolved com-object: a ref merged onto its base.
#[derive(Debug, Clone)]
pub struct ResolvedComObject<'a> {
    /// The base object.
    pub base: &'a ComObject,
    /// The ref pointing at it.
    pub cref: &'a ComObjectRef,
}

impl ResolvedComObject<'_> {
    /// The effective object number.
    pub fn number(&self) -> u16 {
        self.base.number
    }

    /// The effective DPT (ref overrides base).
    pub fn dpt(&self) -> Option<Dpt> {
        self.cref.dpt.or(self.base.dpt)
    }

    /// The effective object size (ref overrides base).
    pub fn object_size(&self) -> Option<&str> {
        self.cref
            .object_size
            .as_deref()
            .or(self.base.object_size.as_deref())
    }

    /// The effective display text (ref overrides base, falling back to name).
    pub fn text(&self) -> Option<&str> {
        self.cref
            .text
            .as_deref()
            .or(self.base.text.as_deref())
            .or(self.base.name.as_deref())
    }

    /// The effective function text (ref overrides base).
    pub fn function_text(&self) -> Option<&str> {
        self.cref
            .function_text
            .as_deref()
            .or(self.base.function_text.as_deref())
    }

    /// The ref's `TextParameterRefId` (app-relative), which fills the
    /// `{{0}}` placeholder of [`Self::text`].
    pub fn text_parameter_ref(&self) -> Option<&str> {
        self.cref.text_parameter_ref.as_deref()
    }

    /// The effective flags: base merged with the ref (ref wins per-flag).
    pub fn flags(&self) -> bussard_model::Flags {
        self.base.flags.merge(self.cref.flags).to_flags()
    }

    /// The declared priority (ref overrides base), `None` when neither
    /// declares one.
    pub fn declared_priority(&self) -> Option<bussard_model::Priority> {
        self.cref.priority.or(self.base.priority)
    }

    /// The effective priority: the declared one, else Low.
    pub fn priority(&self) -> bussard_model::Priority {
        self.declared_priority().unwrap_or_default()
    }
}

/// A parameter type: the shape (int/enum/text/float/none) plus its size.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ParameterType {
    /// `<TypeNumber>`: a bounded integer.
    Int {
        /// Size in bits.
        size_bits: Option<u32>,
        /// Inclusive minimum, if declared.
        min: Option<i64>,
        /// Inclusive maximum, if declared.
        max: Option<i64>,
        /// Whether the encoding is signed (`Type="signedInt"`).
        signed: bool,
    },
    /// `<TypeRestriction>`: an enumeration of value/text pairs.
    Enum {
        /// Size in bits.
        size_bits: Option<u32>,
        /// The `(value, text)` pairs, in document order.
        values: Vec<EnumValue>,
    },
    /// `<TypeText>`: a fixed-length string.
    Text {
        /// Size in bits (length in bytes is `size_bits / 8`).
        size_bits: Option<u32>,
    },
    /// `<TypeFloat>`: a KNX float parameter.
    Float {
        /// Encoding string, e.g. `"DPT 9"`.
        encoding: Option<String>,
        /// Inclusive minimum, if declared.
        #[serde(with = "crate::serde_bits")]
        min: Option<f64>,
        /// Inclusive maximum, if declared.
        #[serde(with = "crate::serde_bits")]
        max: Option<f64>,
    },
    /// `<TypeNone>`: a marker type carrying no memory value.
    None,
    /// `<TypeColor Space="…">`: a colour, written in the model as `#` and two
    /// hex digits per component (`#FF0000`) and placed in memory as one
    /// octet per component (issue #616).
    Color {
        /// The declared colour space: how many components and what they mean.
        space: ColorSpace,
    },
    /// Any other type element (e.g. `TypeColor`, `TypeTime`, `TypePicture`),
    /// preserved by name so nothing is silently dropped.
    Other {
        /// The type element's local name, e.g. `"TypeTime"`.
        kind: String,
        /// Size in bits, if the element declared one.
        size_bits: Option<u32>,
        /// The `Unit` attribute, if declared (a `<TypeTime>`'s `Seconds`,
        /// `PackedDaysHoursMinutesAndSeconds`, ...).
        unit: Option<String>,
    },
}

/// A named parameter type declaration (`<ParameterType>` wrapping one shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParameterTypeDecl {
    /// The full XML `Id`.
    pub id: String,
    /// The declared `Name`.
    pub name: Option<String>,
    /// The concrete shape.
    pub kind: ParameterType,
}

/// A `<Parameter>` definition.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Parameter {
    /// The full XML `Id`.
    pub id: String,
    /// The `Name`.
    pub name: Option<String>,
    /// The display `Text`.
    pub text: Option<String>,
    /// The `ParameterType` id this parameter uses.
    pub parameter_type: Option<String>,
    /// The default `Value`.
    pub default: Option<String>,
    /// The `Access` attribute (`None`/`Read`/`ReadWrite`).
    pub access: Option<String>,
    /// The `SuffixText` attribute: the unit ETS shows after the value field
    /// (`"s"`, `"min"`, `"\u{b0}C"`). It is display metadata, not part of the
    /// encoding, and is absent on most parameters.
    pub suffix_text: Option<String>,
    /// The memory location this parameter's value occupies, if any.
    pub memory: Option<Memory>,
    /// For a **module** parameter, the module-`<Argument>` id whose
    /// per-instance value is added to the parameter's default value (the
    /// `BaseValue` attribute). A Jung 230021SU input module declares its
    /// "internal group communication" parameter with `Value="0"
    /// BaseValue="MD-1_A-19"`, so each instance's default is its argument
    /// value, and `<choose>` branches on it select that instance's refs (issue
    /// #126). `None` for a parameter without one.
    pub base_value: Option<String>,
    /// The interface-object property this parameter's value occupies, when it
    /// lives in a property rather than in memory (`<Property ObjectIndex|ObjectType
    /// PropertyId Offset BitOffset>`). An `LdCtrlWriteProp` without `InlineData`
    /// writes the value these parameters compose (issue #390).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<PropertyLocation>,
    /// Whether the parameter declares `LegacyPatchAlways="true"`: ETS writes
    /// it at its default even while the configuration hides it, whatever
    /// the application's `DownloadInvisibleParameters` says (issue #450).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_patch_always: bool,
    /// For a `TypeText` parameter, the `InitialValue` ETS starts a new device
    /// with, in the language the program was parsed in (its
    /// `<Translation AttributeName="InitialValue">`, else the untranslated
    /// attribute). It wins over the parameter's and its refs' `Value` as the
    /// default (issue #473: the Busch-Wächter PRO 2800's device name is
    /// "Busch-Wächter Pro" in a German project). `None` for any other type
    /// and for a text parameter without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<String>,
}

impl Parameter {
    /// The value ETS gives the parameter on a new device: its
    /// [`Self::initial_value`], else its `Value`.
    pub fn starting_value(&self) -> Option<&str> {
        self.initial_value.as_deref().or(self.default.as_deref())
    }
}

/// Where a property-located parameter sits: the interface object (by index or
/// by type and occurrence), the property id, and the byte and bit offset inside
/// the property value.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PropertyLocation {
    /// `ObjectIndex`, when the object is named by index.
    pub object_index: Option<u32>,
    /// `ObjectType`, when the object is named by type.
    pub object_type: Option<u32>,
    /// `Occurrence` of the object type (absent = the first, 0).
    pub occurrence: Option<u32>,
    /// `PropertyId`.
    pub property_id: u32,
    /// Byte offset inside the property value (all elements concatenated).
    pub offset: u32,
    /// Bit offset inside that byte, MSB first.
    pub bit_offset: u8,
}

/// A `<ParameterRef>`: a reference to a [`Parameter`] with optional overrides.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ParameterRef {
    /// The full XML `Id`.
    pub id: String,
    /// The `Parameter` id this ref points at.
    pub ref_id: String,
    /// A `Value` override, if present.
    pub value: Option<String>,
    /// An `Access` override, if present.
    pub access: Option<String>,
    /// A `Text` override (translation applied), if present: the label
    /// ETS shows for this ref instead of the parameter's own `Text`.
    pub text: Option<String>,
}

/// A code segment (`<RelativeSegment>` / `<AbsoluteSegment>`).
///
/// Beyond the metadata, ETS may carry the segment's binary image inline as a
/// base64 `<Data>` child (the bytes to download into device memory) and, for
/// some segments, a base64 `<Mask>` child marking which bytes the image
/// actually owns. bussard decodes both eagerly into owned `Vec<u8>`: segment
/// images are bounded by the application's declared size (tens of KB at most),
/// so holding them is cheap and lets the download engine and the parameter
/// image builder read them directly. The binary never reaches the emitted YAML
/// models; it is a download input only.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CodeSegment {
    /// The full XML `Id`.
    pub id: String,
    /// Whether this is a relative or absolute segment.
    pub kind: SegmentKind,
    /// Declared `Size` in bytes, if present.
    pub size: Option<u32>,
    /// For absolute segments, the `Address`; for relative, the `Offset`.
    pub address_or_offset: Option<u32>,
    /// `LoadStateMachine` index, for relative segments.
    pub load_state_machine: Option<u32>,
    /// The decoded `<Data>` payload: the segment's base image bytes, if the
    /// element carried one. `None` for a self-closing (metadata-only) segment.
    pub data: Option<Vec<u8>>,
    /// The decoded `<Mask>` payload, where present: a per-byte ownership mask
    /// parallel to `data` (`0xFF` = this byte belongs to the segment image).
    pub mask: Option<Vec<u8>>,
}

/// Which flavour of code segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SegmentKind {
    /// A `<RelativeSegment>`.
    Relative,
    /// An `<AbsoluteSegment>`.
    Absolute,
}

/// The `Mode` and `Fill` octets of a relative allocation (`LdCtrlRelSegment`),
/// octets 6 and 7 of the Data Relative Allocation record (KNX 3/5/3 §3.5.1.2).
///
/// ETS copies the product's `@Mode` and `@Fill` into the record verbatim, also
/// when `Mode` is `0` and the fill octet has no effect on the device: the
/// synthetic product `syn-relseg-fill` (`Mode="0" Fill="255"`) is allocated
/// with `00 ff` (issue #480).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SegmentFill {
    /// The `Mode` octet; bit 0 asks the device to fill the segment.
    pub mode: u8,
    /// The `Fill` octet: the fill byte when bit 0 of `mode` is set, sent
    /// as given otherwise.
    pub fill: u8,
}

impl SegmentFill {
    /// `Mode` 0 and `Fill` 0: no pre-fill (the DA.tp shape and every table
    /// object allocation ETS sends).
    pub const NONE: SegmentFill = SegmentFill { mode: 0, fill: 0 };

    /// `Mode` 1 with fill byte `byte`: the device pre-fills the segment.
    #[must_use]
    pub const fn filled(byte: u8) -> SegmentFill {
        SegmentFill {
            mode: 1,
            fill: byte,
        }
    }

    /// The byte the device pre-fills the segment with: `Some(fill)` when bit 0
    /// of `mode` is set, `None` when the segment keeps its contents.
    #[must_use]
    pub const fn prefill(self) -> Option<u8> {
        if self.mode & 0x01 != 0 {
            Some(self.fill)
        } else {
            None
        }
    }
}

/// One step of a load procedure, a faithful (uninterpreted) representation of an
/// `LdCtrl*` element. Known control ops get a typed variant carrying the
/// attributes phase-3 (`bussard-download`) will need; unrecognized ops are kept
/// verbatim as [`LoadOp::Raw`] so nothing is lost.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LoadOp {
    /// `<LdCtrlConnect>`.
    Connect,
    /// `<LdCtrlDisconnect>`.
    Disconnect,
    /// `<LdCtrlRestart>`.
    Restart,
    /// `<LdCtrlMerge MergeId=…>`: a splice marker in a **master-template**
    /// `Load` procedure (`knx_master.xml`). It is not an on-wire operation: when
    /// a merged application is assembled against the master template, each
    /// `Merge` marker is replaced by the ops of the application's
    /// `<LoadProcedure MergeId="N">` block with the matching id (an unmatched
    /// marker is dropped). Application XML files never carry `LdCtrlMerge`
    /// themselves; the marker exists only so the template's op list is a faithful
    /// record of where the per-object app blocks splice in.
    Merge {
        /// The `MergeId` this marker splices; matched against an application's
        /// `<LoadProcedure MergeId=…>` blocks.
        merge_id: Option<String>,
    },
    /// `<LdCtrlMasterReset EraseCode=… ChannelNumber=…>`: a device Master Reset,
    /// realised on the wire as an `A_Restart` request with the master-reset
    /// restart-type bit set. Unlike a basic `Restart` (fire-and-forget), the
    /// device answers with an `A_Restart_Response` (error code + minimum
    /// process time) and then restarts, dropping the connection. KNX Virtual's
    /// own apps use this mid-procedure (`RelSegment → MasterReset →
    /// WriteRelMem`), so the download engine reconnects and resumes after it.
    MasterReset {
        /// The erase code (`EraseCode`): what the master reset clears. `1` =
        /// Confirmed Restart, `4` = the value KNX Virtual's apps carry. Encoded
        /// verbatim into the `A_Restart` request.
        erase_code: Option<u32>,
        /// The channel number (`ChannelNumber`) the erase applies to (`0` for
        /// the whole device in every observed procedure).
        channel_number: Option<u32>,
    },
    /// `<LdCtrlUnload LsmIdx=…>`.
    Unload {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
    },
    /// `<LdCtrlLoad LsmIdx=…>`.
    Load {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
    },
    /// `<LdCtrlLoadCompleted LsmIdx=…>`.
    LoadCompleted {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
    },
    /// `<LdCtrlTaskSegment LsmIdx=… Address=…>`.
    TaskSegment {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
        /// Target address.
        address: Option<u32>,
    },
    /// `<LdCtrlTaskCtrl1 LsmIdx=… Address=… Count=…>`.
    TaskCtrl1 {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
        /// Target address.
        address: Option<u32>,
        /// Repeat count.
        count: Option<u32>,
    },
    /// `<LdCtrlTaskPtr LsmIdx=… InitPtr=… SavePtr=… SerialPtr=…>`: the Task
    /// Pointer Record (Additional Load Controls segment type 03h, KNX 3/5/2
    /// §3.31.2).
    TaskPtr {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
        /// `InitPtr`: the init address.
        init_ptr: Option<u32>,
        /// `SavePtr`: the save address.
        save_ptr: Option<u32>,
        /// `SerialPtr`: the PEI handler address.
        serial_ptr: Option<u32>,
    },
    /// `<LdCtrlTaskCtrl2 LsmIdx=… Callback=… Address=… Seg0=… Seg1=…>`: Task
    /// Control Record 2 (Additional Load Controls segment type 05h, KNX 3/5/2
    /// §3.31.2).
    TaskCtrl2 {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
        /// `Callback`: the callback address.
        callback: Option<u32>,
        /// `Address`: the group-object table pointer.
        address: Option<u32>,
        /// `Seg0`: the first group-object segment pointer.
        seg0: Option<u32>,
        /// `Seg1`: the second group-object segment pointer.
        seg1: Option<u32>,
    },
    /// `<LdCtrlRelSegment …>`: a relative-segment control op.
    RelSegment {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
        /// Declared size in bytes.
        size: Option<u32>,
        /// `AppliesTo` filter (e.g. `"full"`, `"par"`, `"full,par"`).
        applies_to: Option<String>,
        /// The op's `Mode` and `Fill` octets (or the older `Fill` / `FillByte`
        /// spelling), as the allocation record carries them. With the mode's
        /// fill bit set the device pre-fills the freshly allocated segment
        /// (the app-code segment on some products, e.g. Jung LED A-3030 obj4
        /// alloc `030b000028c1 01 00 0000`); with it clear the `Fill` octet is
        /// still sent as given (ETS does, issue #480). No attribute at all is
        /// [`SegmentFill::NONE`], the DA.tp shape.
        fill: SegmentFill,
    },
    /// `<LdCtrlAbsSegment …>`: an absolute-segment control op.
    AbsSegment {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
        /// Target address.
        address: Option<u32>,
        /// Declared size in bytes.
        size: Option<u32>,
        /// `Access` attribute: the segment's access-attribute octet as ETS puts
        /// it into the allocation record (`242` = `0xF2`, `243` = `0xF3` on the
        /// Jung System 7 apps).
        access: Option<u32>,
        /// `MemType` attribute: `2` = RAM, `3` = EEPROM.
        mem_type: Option<u32>,
        /// `SegFlags` attribute: `128` marks a checksum-controlled segment,
        /// `0` a segment the application rewrites at runtime.
        seg_flags: Option<u32>,
        /// `SegType` attribute: the Additional Load Controls segment type the
        /// allocation goes out as, `0` = AllocAbsDataSeg (absent), `1` =
        /// AllocAbsStackSeg (KNX 3/5/2 §3.31.2, §3.31.3.4; issue #487).
        seg_type: Option<u32>,
    },
    /// `<LdCtrlWriteRelMem …>`: write into relative (parameter) memory.
    WriteRelMem {
        /// Object index.
        obj_idx: Option<u32>,
        /// Byte offset.
        offset: Option<u32>,
        /// Size in bytes.
        size: Option<u32>,
        /// `AppliesTo` filter.
        applies_to: Option<String>,
    },
    /// `<LdCtrlWriteMem …>`: write into absolute memory.
    WriteMem {
        /// Target address.
        address: Option<u32>,
        /// Size in bytes.
        size: Option<u32>,
    },
    /// `<LdCtrlWriteProp …>`: write an interface-object property. The value to
    /// write is the hex `InlineData` attribute (same encoding as
    /// [`LoadOp::CompareProp`]'s `InlineData`); a bare `LdCtrlWriteProp` with no
    /// `InlineData` carries no value (the device seeds the property itself on
    /// `LoadCompleted`).
    WriteProp {
        /// Object index (`ObjIdx`), when addressed by index.
        obj_idx: Option<u32>,
        /// Object type (`ObjType`), when addressed by type.
        obj_type: Option<u32>,
        /// Property id.
        prop_id: Option<u32>,
        /// The value bytes to write, decoded from the hex `InlineData` attribute.
        /// `None` for a bare op that carries no value.
        inline_data: Option<Vec<u8>>,
        /// `StartElement`: the 1-based element the value is written from
        /// (absent = element 1). ETS writes one element per request from here.
        start_element: Option<u32>,
        /// `Count`: how many elements the value spans (absent = 1). The
        /// IPS 300 SREG writes its eight preferred tunnel addresses as one
        /// `Count="8"` property value (issue #390).
        count: Option<u32>,
        /// `Verify`: whether ETS reads the property back after writing it and
        /// fails the download on a difference (absent = `false`).
        verify: Option<bool>,
        /// `Occurrence`: which object of `ObjType` the op addresses when it
        /// names the object by type (absent = the first, 0).
        occurrence: Option<u32>,
    },
    /// `<LdCtrlCompareProp …>`: read an interface-object property and compare it
    /// against expected data — the verify twin of [`LoadOp::WriteProp`]. The
    /// procedure fails the flash if the device's stored property does not match.
    ///
    /// Real vendor shape (MDT SCN-DA64x DALI gateway, Theben, L&J):
    /// `<LdCtrlCompareProp InlineData="00000001620100000000" [Mask="00010000"]
    /// ObjIdx="0" PropId="78"><OnError Cause="CompareMismatch" …/></LdCtrlCompareProp>`.
    /// The expected value is the hex `InlineData` attribute; an optional hex
    /// `Mask` (same length) AND-masks both sides before comparing (`FF` = compare
    /// this byte, `00` = ignore). Some elements express the expectation as a
    /// numeric `Range` instead of `InlineData`; the `<OnError>` children carry only
    /// diagnostic message refs and are not needed to execute the compare.
    CompareProp {
        /// The interface object index (`ObjIdx`), when addressed by index.
        obj_idx: Option<u32>,
        /// The object type (`ObjType`), when addressed by type instead of index.
        obj_type: Option<u32>,
        /// The property id (`PropId`) to read and compare.
        prop_id: Option<u32>,
        /// The expected property bytes, decoded from the hex `InlineData`
        /// attribute. `None` when the op expresses its expectation as a `Range`
        /// (or carried no `InlineData`).
        inline_data: Option<Vec<u8>>,
        /// The comparison mask, decoded from the hex `Mask` attribute (same length
        /// as `inline_data`); each `0xFF` byte is compared, each `0x00` ignored.
        /// `None` means compare every byte.
        mask: Option<Vec<u8>>,
        /// The raw `Range` attribute (e.g. `"[2216203124736,]"`), when the op
        /// expresses its expectation as a numeric range rather than `InlineData`.
        range: Option<String>,
        /// `Occurrence`: which object of `ObjType` the op addresses when it
        /// names the object by type (absent = the first, 0).
        occurrence: Option<u32>,
        /// `StartElement`: the 1-based array element the compare reads (absent
        /// = 1). The Siemens 07B0 applications compare elements 1, 2, 3, 5 and 6
        /// of object 4's PID 246 one by one (issue #614).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        start_element: Option<u32>,
    },
    /// `<LdCtrlCompareRelMem …>`: read relative (segment-relative) memory and
    /// compare it against expected data — the memory twin of
    /// [`LoadOp::CompareProp`] and the verify counterpart of
    /// [`LoadOp::WriteRelMem`]. The procedure fails the flash if the device's
    /// stored memory does not match.
    ///
    /// Real vendor shape (MDT BE-GTSx6Tx and MDT JTA blind push button, both mask
    /// 07B0): `<LdCtrlCompareRelMem InlineData="FF" [Mask="FF"] [Invert="true"]
    /// ObjIdx="4" Offset="1234" Size="1" />`. The expected value is the hex
    /// `InlineData` attribute; an optional hex `Mask` (same length) AND-masks both
    /// sides before comparing (`FF` = compare this byte, `00` = ignore). `Invert`,
    /// when true, inverts the sense of the comparison (the read must *differ* from
    /// the expected bytes under the mask). The read address is
    /// `segment base + Offset`, where the segment base is the `ObjIdx` object's
    /// `PID_TABLE_REFERENCE`, resolved at flash time exactly as
    /// [`LoadOp::WriteRelMem`] resolves its write base.
    CompareRelMem {
        /// The interface object index (`ObjIdx`) whose segment base is read from
        /// `PID_TABLE_REFERENCE`; the compare reads `base + offset`.
        obj_idx: Option<u32>,
        /// The byte offset within the object's segment (`Offset`).
        offset: Option<u32>,
        /// The number of octets to read and compare (`Size`).
        size: Option<u32>,
        /// The expected memory bytes, decoded from the hex `InlineData` attribute.
        /// `None` when the op carried no `InlineData`.
        inline_data: Option<Vec<u8>>,
        /// The comparison mask, decoded from the hex `Mask` attribute (same length
        /// as `inline_data`); each `0xFF` byte is compared, each `0x00` ignored.
        /// `None` means compare every byte.
        mask: Option<Vec<u8>>,
        /// Whether the comparison sense is inverted (`Invert="true"`): when set,
        /// the device memory must *differ* from `inline_data` under the mask for
        /// the check to pass. `false` (the default) requires an exact match.
        invert: bool,
    },
    /// `<LdCtrlLoadImageProp …>`: load-image property integrity check. After a
    /// loadable object's image is written and the object reaches `Loaded`, the
    /// tool reads the object's `PropId` (27 = `PID_MCB_TABLE`) memory control
    /// block and validates the device-computed CRC over the segment against the
    /// image the tool wrote. Carries the target object index (`ObjIdx`) or, for
    /// system objects, an object type + occurrence.
    LoadImageProp {
        /// The interface object index (`ObjIdx`), when the op targets an object
        /// by index (the common case: `ObjIdx=1..4`).
        obj_idx: Option<u32>,
        /// The object type (`ObjType`), when the op targets a system object by
        /// type + occurrence instead of by index.
        obj_type: Option<u32>,
        /// The occurrence of that object type (`Occurrence`), 1-based.
        occurrence: Option<u32>,
        /// The property id (`PropId`); 27 = `PID_MCB_TABLE` in every observed
        /// vendor procedure.
        prop_id: Option<u32>,
        /// How many MCB array elements to read (`Count`), defaulting to 1.
        count: Option<u32>,
    },
    /// `<LdCtrlMapError OriginalError=… MappedError=…>`: an ETS tool-side rule,
    /// not a device operation (the KNX Standard has no such load control). From
    /// this op on, the tool reports the error `OriginalError` of a following
    /// step as `MappedError` (0 = success); a later `LdCtrlMapError` for the same
    /// code replaces the rule, and one that maps the code to itself ends it.
    /// The 27 Siemens 07B0 applications of the corpus (issue #614) map
    /// `0xC0042B08` to 0 for the `LdCtrlUnload LsmIdx="5"` that follows, then
    /// back to itself.
    MapError {
        /// The ETS error code the rule rewrites (`OriginalError`).
        original_error: Option<u32>,
        /// The code it is reported as (`MappedError`); 0 means success.
        mapped_error: Option<u32>,
    },
    /// Any other `LdCtrl*` element, preserved by name and attribute list.
    Raw {
        /// The element's local name (e.g. `"LdCtrlLoadImageProp"`).
        name: String,
        /// Its attributes as `(key, value)` pairs, in document order.
        attrs: Vec<(String, String)>,
    },
}

/// A named load procedure (`<LoadProcedure>`), a list of ordered ops. The
/// `MergeId` groups merged procedures; bussard keeps it for later ordering.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LoadProcedure {
    /// The `MergeId`, if this is part of a merged procedure.
    pub merge_id: Option<String>,
    /// The ordered control operations.
    pub ops: Vec<LoadOp>,
    /// The `<choose ParamRefId>` blocks the procedure contains, in document
    /// order. An op inside one runs only when its branch is taken (issue #390:
    /// the MDT 0705 programs write their label properties only when a
    /// parameter selects them). Empty for a procedure without `<choose>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chooses: Vec<LoadChoose>,
    /// Per op, at the same index as [`Self::ops`], the branches the op sits
    /// in, outermost first. Empty for a procedure without `<choose>`; read it
    /// through [`LoadProcedure::guards_of`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guards: Vec<Vec<LoadGuard>>,
    /// Per op, at the same index as [`Self::ops`], its `AppliesTo` attribute
    /// verbatim (`"full"`, `"par"`, `"grp"`, `"full,par"`, ...), `None` when
    /// the op carries none. Read it through [`LoadProcedure::applies_to_of`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<Option<String>>,
}

impl LoadProcedure {
    /// The branches op `index` sits in (empty: unconditional).
    pub fn guards_of(&self, index: usize) -> &[LoadGuard] {
        self.guards.get(index).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The `AppliesTo` attribute of op `index`, `None` when it has none.
    pub fn applies_to_of(&self, index: usize) -> Option<&str> {
        self.applies_to.get(index).and_then(Option::as_deref)
    }

    /// Whether op `index` belongs only to a partial download: its `AppliesTo`
    /// names the parameter (`par`) or group-address (`grp`) download and
    /// neither the complete download (`full`) nor every download (`all`,
    /// `auto`).
    pub fn is_partial_only(&self, index: usize) -> bool {
        self.applies_to_of(index)
            .is_some_and(applies_to_partial_only)
    }

    /// Whether the procedure lists the group-address download (an op with
    /// `AppliesTo="grp"` only) next to the complete one. The Siemens 07B0
    /// product procedures (issue #614) list the complete, parameter and
    /// group-address downloads one after the other in one `<LoadProcedure>`;
    /// a complete download runs none of the [`Self::is_partial_only`] ops of
    /// such a procedure.
    pub fn lists_partial_downloads(&self) -> bool {
        self.applies_to.iter().flatten().any(|scope| {
            let mut tokens = scope.split(',').map(str::trim).filter(|t| !t.is_empty());
            tokens.clone().next().is_some() && tokens.all(|t| t.eq_ignore_ascii_case("grp"))
        })
    }
}

/// Whether an `AppliesTo` value names only partial downloads (`par`, `grp`)
/// and not the complete one (`full`, `all`, `auto`). An empty value applies to
/// every download.
pub fn applies_to_partial_only(applies_to: &str) -> bool {
    let tokens: Vec<&str> = applies_to
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|t| t.eq_ignore_ascii_case("par") || t.eq_ignore_ascii_case("grp"))
}

/// A `<choose ParamRefId>` inside a `<LoadProcedure>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoadChoose {
    /// The app-relative `ParameterRef` id whose value selects the branch.
    pub param_ref_id: String,
    /// Each `<when>` branch's test, in document order.
    pub tests: Vec<WhenTest>,
}

/// One `<when>` branch an op of a [`LoadProcedure`] sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoadGuard {
    /// Index into [`LoadProcedure::chooses`].
    pub choose: usize,
    /// Index into that choose's [`LoadChoose::tests`].
    pub branch: usize,
}

/// A table's place inside a code segment, as `<Static>` declares it
/// (`<ComObjectTable CodeSegment=… Offset=…>`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TableLocation {
    /// The full `Id` of the code segment holding the table.
    pub code_segment: String,
    /// The table's byte offset inside that segment.
    pub offset: u32,
}

/// The Data Secure table capacities an application declares (issue #537):
/// how many entries the device's group key table (PID 53), security
/// individual address table (PID 54) and point-to-point key table hold. ETS
/// sizes the download with them; KNX 3/5/1 §6.3.7 and §6.3.8 leave the
/// capacity to the device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecurityCapacity {
    /// `MaxSecurityGroupKeyTableEntries`.
    pub group_key_table_entries: Option<u32>,
    /// `MaxSecurityIndividualAddressEntries`.
    pub individual_address_entries: Option<u32>,
    /// `MaxSecurityP2PKeyTableEntries`.
    pub p2p_key_table_entries: Option<u32>,
}

impl SecurityCapacity {
    /// Whether the application declares none of the figures.
    pub fn is_empty(&self) -> bool {
        self.group_key_table_entries.is_none()
            && self.individual_address_entries.is_none()
            && self.p2p_key_table_entries.is_none()
    }
}

/// One parsed ApplicationProgram.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ApplicationProgram {
    /// The application-program id (e.g. `M-0004_A-20D7-26-053C-O000A`).
    pub id: String,
    /// `ApplicationNumber`.
    pub application_number: Option<u32>,
    /// `ApplicationVersion` as a parsed number.
    pub application_version: Option<u32>,
    /// `ApplicationVersion` as the raw attribute string (project keeps this
    /// verbatim for device provenance).
    pub version: Option<String>,
    /// The mask version with the `MV-` prefix stripped, e.g. `"07B0"`.
    pub mask_version: Option<String>,
    /// `PeiType`: the physical external interface the application needs. A
    /// System 7 download writes it into every TaskSegment record (`1` on the
    /// Ekinex EK-E72, `128` on the Busch-Jaeger A-A002).
    #[serde(default)]
    pub pei_type: Option<u8>,
    /// `OriginalManufacturer` (e.g. `M-0002`): the manufacturer that made an
    /// application another manufacturer sells.
    #[serde(default)]
    pub original_manufacturer: Option<String>,
    /// Whether `<Options>` declares
    /// `LegacyPatchManufacturerIdInTaskSegment="true"`: a System 7 TaskSegment
    /// record then carries [`Self::original_manufacturer`] instead of the
    /// manufacturer in the application id.
    #[serde(default)]
    pub legacy_patch_manufacturer_in_task_segment: bool,
    /// Whether the program declares an ETS download plugin
    /// (`<Extension EtsDownloadPlugin=...>`, even an empty one). ETS then
    /// writes the System B group-object table with the communication flag
    /// on every declared object (issue #565, the Busch-Jaeger DALI gateways).
    #[serde(default)]
    pub ets_download_plugin: bool,
    /// Whether `<Options>` declares `SupportsExtendedMemoryServices="true"`.
    /// ETS reads and writes memory above `0xFFFF` with
    /// `A_MemoryExtended_*` when it does and with `A_UserMemory_*` when it
    /// does not (issue #472, the sweep over Zennio, ABB and Busch-Jaeger).
    #[serde(default)]
    pub supports_extended_memory_services: bool,
    /// Application-program display name (translation applied).
    pub name: Option<String>,
    /// The declared `DefaultLanguage`: the language of the untranslated
    /// attributes, e.g. `en-US`.
    pub default_language: Option<String>,
    /// The declared `LoadProcedureStyle`.
    pub load_procedure_style: Option<String>,
    /// The declared `ProgramType`: absent (or `ApplicationProgram`) for an
    /// application, `PeiProgram` for the second program a device loads next to
    /// it (the ABB BE/S16.230.3.2 loads `A-A0ED-20` into object 5).
    pub program_type: Option<String>,
    /// The other programs the same `Hardware2Program` loads alongside this one
    /// (a `PeiProgram`), attached by the product reader. A download of this
    /// application runs their merged load-procedure blocks and streams their
    /// segments too, as ETS does. Empty for a single-program device.
    pub companion_programs: Vec<ApplicationProgram>,
    /// Whether the application declares `IsSecureEnabled="true"`: it is KNX
    /// Data-Secure-capable (issue #71, spec §11). Capability, not activation.
    pub is_secure_enabled: bool,
    /// The application's Data Secure table capacities (issue #537): the
    /// `MaxSecurity*` attributes of `<ApplicationProgram>`. All `None` when
    /// the application declares none.
    #[serde(default)]
    pub security_capacity: SecurityCapacity,
    /// `AdditionalAddressesCount`: how many tunnelling addresses the device's
    /// KNXnet/IP parameter object holds (`PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`)
    /// on hardware with a KNX IP interface built in (the Zennio ALLinBOX 1612
    /// declares 5). ETS writes exactly that many after the download (issue
    /// #455). `None` when the application declares none.
    #[serde(default)]
    pub additional_addresses_count: Option<u16>,
    /// The XML schema version this file declared, e.g. `"20"`, `"21"`, `"23"`.
    pub schema_version: Option<String>,
    /// The `<Options DownloadInvisibleParameters>` value (`None`, `Background`),
    /// or `None` when the application declares no such attribute. It says
    /// whether a download writes the parameters the configuration does not
    /// show; see [`Self::downloads_invisible_parameters`].
    pub download_invisible_parameters: Option<String>,
    /// Whether `<Options>` declares `PreferPartialDownloadIfApplicationLoaded="true"`.
    pub prefer_partial_download: bool,
    /// Whether the application declares `DynamicTableManagement` (`1` or
    /// `true`). On System 7 ETS then sizes the address-table segment to the
    /// table and allocates the association table directly behind it, instead
    /// of at the product's static LSM 2 address (issue #383).
    #[serde(default)]
    pub dynamic_table_management: bool,
    /// Whether `<Options>` declares `ParameterByteOrder="LittleEndian"`: a
    /// multi-octet integer parameter is stored least significant octet first
    /// (the ABB 6119/20 `A-A002` writes debounce 5633 as `01 16`, issue #386).
    /// `false` for `BigEndian` or no declaration, the KNX default.
    #[serde(default)]
    pub parameters_little_endian: bool,
    /// The `<Options TextParameterEncoding>` value (`iso-8859-15`, `utf-8`,
    /// ...): the code page a `TypeText` parameter is converted to octets with
    /// (issue #401). `None` when the program declares none.
    #[serde(default)]
    pub text_parameter_encoding: Option<String>,
    /// Where `<Static><ComObjectTable CodeSegment Offset>` places the
    /// group-object table inside a code segment, when the program declares
    /// it. A System 7 (mask 07xx) program keeps its descriptor table there.
    #[serde(default)]
    pub com_object_table: Option<TableLocation>,
    /// Base com-objects, keyed by full `Id`.
    pub com_objects: HashMap<String, ComObject>,
    /// Com-object refs, keyed by full `Id`.
    pub com_object_refs: HashMap<String, ComObjectRef>,
    /// Parameter type declarations, keyed by full `Id`.
    pub parameter_types: HashMap<String, ParameterTypeDecl>,
    /// Parameters, keyed by full `Id`.
    pub parameters: HashMap<String, Parameter>,
    /// `<Union>` blocks, in document order. Each overlays several member
    /// parameters onto one shared memory region; empty for an application with
    /// no unions.
    pub unions: Vec<Union>,
    /// Parameter refs, keyed by full `Id`.
    pub parameter_refs: HashMap<String, ParameterRef>,
    /// Code segments, keyed by full `Id`.
    pub code_segments: HashMap<String, CodeSegment>,
    /// Load procedures, in document order.
    pub load_procedures: Vec<LoadProcedure>,
    /// Dynamic-section channel definitions, keyed by the app-relative channel id
    /// (e.g. `MD-1_CH-13`, or `CH-2` for a non-module channel).
    pub channels: HashMap<String, ChannelDef>,
    /// Every Dynamic-section `<Channel>` with its id, `Number` and
    /// `TextParameterRefId`, keyed like [`Self::channels`]. Unlike
    /// [`ChannelDef`], the `Text` here has the translation applied.
    pub channel_refs: HashMap<String, ChannelRef>,
    /// Module `<Argument>` name → app-relative argument id (e.g.
    /// `ArgBeschriftung` → `MD-1_A-3`), used to resolve `{{Arg…}}` placeholders
    /// in channel and com-object texts against a module instance's values.
    pub argument_ids: HashMap<String, String>,
    /// The `Allocates` of every module `<Argument>` that declares one, keyed
    /// by app-relative argument id (issue #449): how far an allocator-fed
    /// value of the argument advances its allocator.
    #[serde(default)]
    pub argument_allocates: HashMap<String, i64>,
    /// The `<Allocator>`s of the application's and the module definitions'
    /// `<Static>`, keyed by app-relative id (`L-2`, `MD-1_L-1`) (issue #449).
    #[serde(default)]
    pub allocators: HashMap<String, Allocator>,
    /// Dynamic-section `<Module>` instantiations, in document order. Each is one
    /// channel's set of argument values; empty for a non-module application.
    pub module_instances: Vec<ModuleInstance>,
    /// Per-channel com-object membership captured from the module definition's
    /// Dynamic `<ParameterBlock>` (which com-object refs each channel
    /// instantiates, unconditionally or under a `<choose>`). `None` for an
    /// application with no module channel membership to expand.
    pub channel_membership: Option<ChannelMembership>,
    /// The application's top-level Dynamic section as a tree (see
    /// [`DynamicNode`]); empty when the program has none.
    pub dynamic: Vec<DynamicNode>,
    /// Each `<ModuleDef>`'s own Dynamic section, keyed by app-relative module
    /// definition id (e.g. `MD-13`); a [`DynamicNode::Module`] reached in
    /// [`Self::dynamic`] evaluates the body stored here.
    pub module_dynamics: HashMap<String, Vec<DynamicNode>>,
}

impl ApplicationProgram {
    /// Whether a download writes the parameters the configuration does not
    /// show, with their defaults.
    ///
    /// Never when `<Options>` declares `DownloadInvisibleParameters` (`None`
    /// or `Background`) or `PreferPartialDownloadIfApplicationLoaded="true"`:
    /// the segment template stays for them on both systems. Without either
    /// attribute ETS 6 writes them on a System B program (mask `xxB0`) at
    /// every schema version, and on a System 7 one (mask `0700`, `0701`,
    /// `0705`) from schema version [`Self::FIRST_SYSTEM7_SCHEMA_WITH_HIDDEN_DEFAULTS`]
    /// on (issues #89 and #448). Established from full-download captures,
    /// each one a hidden parameter whose default differs from its template:
    ///
    /// * System B, neither attribute, defaults written: Busch-Wächter PRO
    ///   280 / 2800 (`M-0007_A-6179-82`, project/20, `MinEtsVersion` 5.0)
    ///   and the synthetic `syn-hidden-default` (project/23).
    /// * System 7, neither attribute, defaults written: the synthetic
    ///   `syn-s7-hidden-default` (0705, project/23).
    /// * System 7, neither attribute, template kept: its twin
    ///   `syn-s7-hidden-default-p11` (project/11, the same product otherwise),
    ///   the sweep's Steinel HPD 2 and TruePresence, ekinex, B.E.G. DIM,
    ///   Zennio Sensato, MDT rain sensor and Elsner rows (project/11), and
    ///   Busch-Jaeger `A-FF11-15` (0705, project/20, `MinEtsVersion` 3.0d,
    ///   14 octets differ when its hidden defaults are written).
    /// * System B, partial download preferred, template kept: Busch-Jaeger
    ///   DALI gateways `A-A0AC`, `A-A0AD`, Zennio DALI-BOX `A-3131`,
    ///   `A-3311`, `A-3331`, Jung 230021SU, 390041SR, F50, ABB BE/S16.
    /// * Declared `None` or `Background`, template kept on both systems.
    ///
    /// The schema version alone does not decide: in project/20 the System B
    /// PRO 280 writes and the System 7 `A-FF11-15` keeps. Not settled: the
    /// System 7 boundary between 21 and 23 (the corpus has no System 7
    /// program in project/21 or /22, so the choice of 21 changes no vendor
    /// product), System B below project/20 (no capture separates it; the
    /// Steinel ControlPro, project/11, has its hidden defaults equal to the
    /// template), and whether ETS keys on `MinEtsVersion` instead (every
    /// capture above that writes has 5.0 or later, every one that keeps has
    /// 4.0 or earlier or none). `syn-s7-hidden-default` rendered in
    /// project/23 with `MinEtsVersion="4.0"` would tell the two apart.
    pub fn downloads_invisible_parameters(&self) -> bool {
        self.download_invisible_parameters.is_none()
            && !self.prefer_partial_download
            && (self.is_system_b()
                || (self.is_system_7()
                    && self
                        .schema_number()
                        .is_some_and(|n| n >= Self::FIRST_SYSTEM7_SCHEMA_WITH_HIDDEN_DEFAULTS)))
    }

    /// The first `http://knx.org/xml/project/<N>` schema version from which
    /// a System 7 program without `DownloadInvisibleParameters` gets the
    /// parameters the configuration does not show written at their defaults
    /// (issue #448; see [`Self::downloads_invisible_parameters`]).
    pub const FIRST_SYSTEM7_SCHEMA_WITH_HIDDEN_DEFAULTS: u32 = 21;

    /// The schema version of [`Self::schema_version`] as a number (`23` for
    /// `http://knx.org/xml/project/23`), `None` when the file declared none
    /// or a non-numeric one.
    pub fn schema_number(&self) -> Option<u32> {
        self.schema_version.as_deref()?.trim().parse().ok()
    }

    /// Whether the program is a System 7 one: its `MaskVersion` is `0700`,
    /// `0701` or `0705`.
    pub fn is_system_7(&self) -> bool {
        self.mask_version
            .as_deref()
            .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
            .is_some_and(|m| matches!(m, 0x0700 | 0x0701 | 0x0705))
    }

    /// Whether the program is a System B one: its `MaskVersion` is `xxB0`
    /// (`07B0` on TP, `27B0`/`57B0` on other media).
    pub fn is_system_b(&self) -> bool {
        self.mask_version
            .as_deref()
            .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
            .is_some_and(|m| m & 0x0FFF == 0x07B0)
    }

    /// Whether this is a `PeiProgram` (a second loadable program, not an
    /// application a device is selected by).
    pub fn is_pei_program(&self) -> bool {
        self.program_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("PeiProgram"))
    }

    /// Iterates resolved com-objects (ref merged onto base) sorted by number,
    /// skipping refs whose base is missing.
    pub fn resolved_com_objects(&self) -> Vec<ResolvedComObject<'_>> {
        let mut out: Vec<ResolvedComObject<'_>> = self
            .com_object_refs
            .values()
            .filter_map(|cref| {
                self.com_objects
                    .get(&cref.ref_id)
                    .map(|base| ResolvedComObject { base, cref })
            })
            .collect();
        out.sort_by(|a, b| {
            a.number()
                .cmp(&b.number())
                .then_with(|| a.cref.id.cmp(&b.cref.id))
        });
        out
    }

    /// Resolves a `ComObjectInstanceRef` `RefId` (relative to this program) to
    /// its effective base + ref, if both resolve.
    ///
    /// The `RefId` on an instance is relative (e.g. `O-0_R-1`); the full ref id
    /// is `<program-id>_<RefId>` and the base id is the ref's `RefId`.
    pub fn resolve(&self, instance_ref_id: &str) -> Option<(&ComObject, &ComObjectRef)> {
        let full_ref_id = format!("{}_{instance_ref_id}", self.id);
        let cor = self.com_object_refs.get(&full_ref_id)?;
        let base = self.com_objects.get(&cor.ref_id)?;
        Some((base, cor))
    }

    /// Resolves an app-relative channel id (e.g. `MD-1_CH-13`) to its definition.
    pub fn channel(&self, app_channel_id: &str) -> Option<&ChannelDef> {
        self.channels.get(app_channel_id)
    }

    /// Resolves an app-relative channel id to its [`ChannelRef`] (id, number,
    /// name, translated text and label parameter).
    pub fn channel_ref(&self, app_channel_id: &str) -> Option<&ChannelRef> {
        self.channel_refs.get(app_channel_id)
    }

    /// Resolves an app-relative `ParameterRef` id (e.g. `MD-1_P-3_R-5`) to
    /// its ref.
    pub fn parameter_ref(&self, app_param_ref_id: &str) -> Option<&ParameterRef> {
        self.parameter_refs
            .get(&format!("{}_{app_param_ref_id}", self.id))
    }

    /// Looks up the app-relative argument id (e.g. `MD-1_A-3`) for an argument
    /// `Name` (e.g. `ArgBeschriftung`).
    pub fn argument_id(&self, name: &str) -> Option<&str> {
        self.argument_ids.get(name).map(String::as_str)
    }

    /// Resolves a parameter ref to its effective value/access/type, applying the
    /// ref's `Value`/`Access` overrides over the parameter's own.
    pub fn resolved_parameter(&self, ref_id: &str) -> Option<ResolvedParameter<'_>> {
        let pref = self.parameter_refs.get(ref_id)?;
        let param = self.parameters.get(&pref.ref_id)?;
        Some(ResolvedParameter { param, pref })
    }
}

/// A parameter ref merged onto its parameter.
#[derive(Debug, Clone)]
pub struct ResolvedParameter<'a> {
    /// The underlying parameter.
    pub param: &'a Parameter,
    /// The ref pointing at it.
    pub pref: &'a ParameterRef,
}

impl ResolvedParameter<'_> {
    /// The effective default value (ref `Value` overrides the parameter's).
    pub fn value(&self) -> Option<&str> {
        self.pref.value.as_deref().or(self.param.default.as_deref())
    }

    /// The effective access (ref `Access` overrides the parameter's).
    pub fn access(&self) -> Option<&str> {
        self.pref.access.as_deref().or(self.param.access.as_deref())
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses an ApplicationProgram XML from raw UTF-8 bytes.
///
/// Taking `&[u8]` lets callers hand the raw (inflated) container entry straight
/// to the parser: `quick-xml` reads UTF-8 out of the byte stream event by event,
/// so we skip an eager whole-file `String` validation of a file that reaches
/// ~28 MB. A leading UTF-8 BOM is stripped here on the bytes.
///
/// `id` is the application-program id (used for error context and as the
/// returned id).
pub fn parse_application_program(id: &str, xml: &[u8]) -> Result<ApplicationProgram> {
    parse_application_program_in(id, xml, crate::translation::DEFAULT_LANGUAGE)
}

/// [`parse_application_program`] with the texts in `language` (an ETS
/// identifier such as `de-DE`): its translations replace the untranslated
/// attributes, and an attribute it does not translate keeps the program's
/// `DefaultLanguage` text.
pub fn parse_application_program_in(
    id: &str,
    xml: &[u8],
    language: &str,
) -> Result<ApplicationProgram> {
    let context = format!("application program {id}");
    // Strip a leading UTF-8 BOM on the bytes so the reader starts on `<`.
    let xml = xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml);
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut app = ApplicationProgram {
        id: id.to_string(),
        ..Default::default()
    };

    // The chosen language's translations, applied after the main pass.
    let mut translations = TranslationCollector::for_language(language);

    // Everything the element handlers accumulate across events (see
    // [`ParseState`]).
    let mut state = ParseState::default();

    // Streaming capture of a code segment's inline binary. When we enter a
    // `<RelativeSegment>`/`<AbsoluteSegment>` with children we record its id;
    // its `<Data>`/`<Mask>` children then feed base64 text into `seg_capture`.
    let mut cur_segment_id: Option<String> = None;
    let mut seg_capture: Option<SegField> = None;
    let mut seg_buf = String::new();

    // A single attribute buffer, reused for every element. Its heap allocations
    // (the pair list and each key/value buffer) are recycled across the whole
    // parse instead of being freed and reallocated per element (issue #58).
    let mut attrs = Attrs::new();

    loop {
        let ev = reader.read_event().map_err(|source| EtsError::Xml {
            context: context.clone(),
            source,
        })?;
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                // A `<Data>`/`<Mask>` child of the current segment: begin
                // buffering its base64 text.
                match e.local_name().as_ref() {
                    b"Data" if cur_segment_id.is_some() => {
                        seg_capture = Some(SegField::Data);
                        seg_buf.clear();
                    }
                    b"Mask" if cur_segment_id.is_some() => {
                        seg_capture = Some(SegField::Mask);
                        seg_buf.clear();
                    }
                    b"RelativeSegment" | b"AbsoluteSegment" => {
                        attrs.parse_into(&e, &context)?;
                        cur_segment_id = get(&attrs, b"Id").map(str::to_string);
                    }
                    _ => {}
                }
                handle_start(
                    &e,
                    &context,
                    &mut app,
                    &mut translations,
                    &mut attrs,
                    &mut state,
                )?;
            }
            Event::Text(t) if seg_capture.is_some() => {
                // Accumulate base64 text (segments can arrive across several
                // text events); trim only when decoding.
                let raw = t.into_inner();
                seg_buf.push_str(&String::from_utf8_lossy(&raw));
            }
            Event::Empty(e) => {
                handle_empty(
                    &e,
                    &context,
                    &mut app,
                    &mut translations,
                    &mut attrs,
                    &mut state,
                )?;
            }
            Event::End(e) => match {
                state.tree.end(e.local_name().as_ref(), Some(&mut app));
                e.local_name()
            }
            .as_ref()
            {
                b"Data" | b"Mask" => {
                    if let (Some(field), Some(seg_id)) =
                        (seg_capture.take(), cur_segment_id.as_deref())
                    {
                        let bytes = decode_segment_base64(&seg_buf, &context, seg_id, field)?;
                        if let Some(seg) = app.code_segments.get_mut(seg_id) {
                            match field {
                                SegField::Data => seg.data = Some(bytes),
                                SegField::Mask => seg.mask = Some(bytes),
                            }
                        }
                    }
                    seg_buf.clear();
                }
                b"RelativeSegment" | b"AbsoluteSegment" => cur_segment_id = None,
                b"Language" => translations.exit_language(),
                b"TranslationElement" => translations.exit_element(),
                b"Parameter" => state.param_id = None,
                b"Union" => {
                    // Close a union: record its base location and members.
                    if let Some(union) = state.union.take() {
                        app.unions.push(union);
                    }
                }
                b"ParameterType" => {
                    if let (Some(pt_id), kind) = (state.pt_id.take(), state.pt_kind.take()) {
                        app.parameter_types.insert(
                            pt_id.clone(),
                            ParameterTypeDecl {
                                id: pt_id,
                                name: state.pt_name.take(),
                                kind: kind.unwrap_or(ParameterType::None),
                            },
                        );
                    }
                    state.pt_name = None;
                }
                b"LoadProcedure" => {
                    if let Some(lp) = state.lp.take() {
                        app.load_procedures.push(lp);
                    }
                    state.lp_frames.clear();
                }
                b"when" if state.lp.is_some() => {
                    if let Some(frame) = state.lp_frames.last_mut() {
                        frame.1 = None;
                    }
                }
                b"choose" if state.lp.is_some() => {
                    state.lp_frames.pop();
                }
                b"when" => {
                    // Close the innermost `<when>`: attach its collected
                    // com-object-ref ids to its own `<choose>` frame.
                    if let Some(frame) = state.dynamic.choose_stack.last_mut()
                        && let Some(branch) = frame.when.take()
                    {
                        // Keep the flattened exact-value view in step: one
                        // entry per listed value (`test="0 2"` yields two).
                        if let WhenTest::Values(values) = &branch.test {
                            for v in values {
                                frame.group.branches.push((*v, branch.members.clone()));
                            }
                        }
                        frame.group.branches_all.push(branch);
                    }
                }
                b"choose" => {
                    // Pop the innermost `<choose>` and attach it to the
                    // membership. A nested group is attached in its own right:
                    // the flat membership cannot express "inner branch AND outer
                    // branch", but each group keeps its own members.
                    if let Some(frame) = state.dynamic.choose_stack.pop()
                        && let Some(mem) = state.dynamic.cur_membership.as_mut()
                    {
                        mem.conditional.push(frame.group);
                    }
                }
                b"ParameterBlock" => {
                    // Close the channel parameter block: capture its membership
                    // once (a module template has a single channel/block).
                    if let Some(mem) = state.dynamic.cur_membership.take()
                        && !state.dynamic.membership_captured
                    {
                        app.channel_membership = Some(mem);
                        state.dynamic.membership_captured = true;
                    }
                    // A `<choose>` left open by malformed XML must not leak into
                    // the next block's frames.
                    state.dynamic.choose_stack.clear();
                }
                b"Module" => {
                    // Close a module instance: record its accumulated arg values.
                    if let Some(module) = state.dynamic.cur_module.take() {
                        app.module_instances.push(module);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    apply_translations(&mut app, &translations);
    // `InitialValue` is the starting value of a text parameter only.
    let types = &app.parameter_types;
    for param in app.parameters.values_mut() {
        let text = param
            .parameter_type
            .as_deref()
            .and_then(|t| types.get(t))
            .is_some_and(|d| matches!(d.kind, ParameterType::Text { .. }));
        if !text {
            param.initial_value = None;
        }
    }
    Ok(app)
}

/// The languages an ApplicationProgram XML offers (see [`program_languages`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramLanguages {
    /// The `DefaultLanguage` of the program: the language of its untranslated
    /// attributes.
    pub default: Option<String>,
    /// The `Identifier` of every `<Language>` translation layer.
    pub translations: BTreeSet<String>,
}

impl ProgramLanguages {
    /// Whether the program's texts exist in `language`, as its default
    /// language or as a translation (compared without regard to case).
    pub fn offers(&self, language: &str) -> bool {
        self.default
            .iter()
            .chain(&self.translations)
            .any(|l| l.eq_ignore_ascii_case(language))
    }
}

/// Reads the languages an ApplicationProgram XML offers with a byte scan, so
/// an importer can choose the language before the (much slower) full parse:
/// the first `DefaultLanguage` attribute and the `Identifier` of every
/// `<Language>` element.
pub fn program_languages(xml: &[u8]) -> ProgramLanguages {
    const DEFAULT: &[u8] = b"DefaultLanguage=\"";
    const LAYER: &[u8] = b"<Language Identifier=\"";
    let value_at = |start: usize| -> Option<String> {
        let rest = xml.get(start..)?;
        let end = rest.iter().position(|&b| b == b'"')?;
        std::str::from_utf8(&rest[..end])
            .ok()
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let mut out = ProgramLanguages::default();
    let mut i = 0;
    while let Some(skip) = xml[i..].iter().position(|&b| b == b'<' || b == b'D') {
        i += skip;
        let rest = &xml[i..];
        if out.default.is_none() && rest.starts_with(DEFAULT) {
            out.default = value_at(i + DEFAULT.len());
            i += DEFAULT.len();
            continue;
        }
        if rest.starts_with(LAYER) {
            if let Some(v) = value_at(i + LAYER.len()) {
                out.translations.insert(v);
            }
            i += LAYER.len();
            continue;
        }
        i += 1;
    }
    out
}

/// Convenience wrapper over [`parse_application_program`] for `&str` callers
/// (chiefly tests). Production callers hand raw bytes to the byte API to avoid
/// an eager UTF-8 validation of a multi-megabyte file.
pub fn parse_application_program_str(id: &str, xml: &str) -> Result<ApplicationProgram> {
    parse_application_program(id, xml.as_bytes())
}

/// Handles a `Start` event (elements that have children).
fn handle_start(
    e: &BytesStart,
    context: &str,
    app: &mut ApplicationProgram,
    translations: &mut TranslationCollector,
    attrs: &mut Attrs,
    state: &mut ParseState,
) -> Result<()> {
    attrs.parse_into(e, context)?;
    let m = &*attrs;
    state.tree.start(e.local_name().as_ref(), m, &app.id);
    match e.local_name().as_ref() {
        b"KNX" => {
            // The XML schema version is declared as the default namespace on the
            // root element, e.g. `http://knx.org/xml/project/23`.
            app.schema_version = get(m, b"xmlns")
                .and_then(|ns| ns.rsplit('/').next())
                .map(str::to_string);
        }
        b"ApplicationProgram" => {
            app.application_number = get(m, b"ApplicationNumber").and_then(|s| s.parse().ok());
            app.application_version = get(m, b"ApplicationVersion").and_then(|s| s.parse().ok());
            app.version = get(m, b"ApplicationVersion").map(str::to_string);
            if let Some(mv) = get(m, b"MaskVersion") {
                app.mask_version = Some(mv.strip_prefix("MV-").unwrap_or(mv).to_string());
            }
            app.pei_type = get(m, b"PeiType").and_then(|s| s.parse().ok());
            app.original_manufacturer = get(m, b"OriginalManufacturer").map(str::to_string);
            app.name = get(m, b"Name").map(str::to_string);
            app.default_language = get(m, b"DefaultLanguage").map(str::to_string);
            app.load_procedure_style = get(m, b"LoadProcedureStyle").map(str::to_string);
            app.program_type = get(m, b"ProgramType").map(str::to_string);
            // KNX Secure capability (issue #71, spec §11): the application
            // declares whether it can run Data Secure. Preserve it (previously
            // dropped); it is a capability flag, not key material.
            app.is_secure_enabled = get(m, b"IsSecureEnabled")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
            // The Data Secure table capacities (issue #537).
            let count = |name: &[u8]| get(m, name).and_then(|v| v.trim().parse::<u32>().ok());
            app.security_capacity = SecurityCapacity {
                group_key_table_entries: count(b"MaxSecurityGroupKeyTableEntries"),
                individual_address_entries: count(b"MaxSecurityIndividualAddressEntries"),
                p2p_key_table_entries: count(b"MaxSecurityP2PKeyTableEntries"),
            };
            app.additional_addresses_count =
                get(m, b"AdditionalAddressesCount").and_then(|v| v.trim().parse::<u16>().ok());
            app.dynamic_table_management = get(m, b"DynamicTableManagement")
                .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");
        }
        b"RelativeSegment" => insert_segment(app, m, SegmentKind::Relative),
        b"AbsoluteSegment" => insert_segment(app, m, SegmentKind::Absolute),
        b"Options" => insert_options(app, m),
        b"Extension" => insert_extension(app, m),
        b"ComObjectTable" => insert_com_object_table(app, m),
        b"Language" => translations.enter_language(get(m, b"Identifier")),
        b"TranslationElement" => translations.enter_element(get(m, b"RefId")),
        b"ComObject" => insert_com_object(app, m),
        b"ComObjectRef" => insert_com_object_ref(app, m),
        b"Channel" => insert_channel(app, m),
        b"Argument" => insert_argument(app, m),
        b"Allocator" => insert_allocator(app, m),
        b"ParameterType" => {
            state.pt_id = get(m, b"Id").map(str::to_string);
            state.pt_name = get(m, b"Name").map(str::to_string);
            state.pt_kind = None;
        }
        b"TypeRestriction" => {
            state.pt_kind = Some(ParameterType::Enum {
                size_bits: get(m, b"SizeInBit").and_then(|s| s.parse().ok()),
                values: Vec::new(),
            });
        }
        b"Parameter" => {
            state.param_id = insert_parameter_start(app, m);
            // A `<Parameter>` directly inside a `<Union>` is a member: record its
            // union-relative Offset/BitOffset and default flag.
            if let (Some(union), Some(pid)) = (state.union.as_mut(), state.param_id.as_ref()) {
                union.members.push(union_member(pid, m));
            }
        }
        b"Union" => {
            // Begin a `<Union SizeInBit=..>`; its `<Memory>` child and member
            // `<Parameter>`s follow.
            state.union = Some(Union {
                size_bits: get(m, b"SizeInBit").and_then(|s| s.parse().ok()),
                memory: None,
                members: Vec::new(),
            });
        }
        b"LoadProcedure" => {
            state.lp = Some(LoadProcedure {
                merge_id: get(m, b"MergeId").map(str::to_string),
                ..LoadProcedure::default()
            });
            state.lp_frames.clear();
        }
        b"Module" => {
            // Begin accumulating a `<Module>` instance's argument values.
            state.dynamic.cur_module = Some(ModuleInstance {
                id: get(m, b"Id")
                    .and_then(|id| app_relative_id(id, &app.id))
                    .map(str::to_string)
                    .unwrap_or_default(),
                module_def: get(m, b"RefId")
                    .and_then(|id| app_relative_id(id, &app.id))
                    .map(str::to_string)
                    .unwrap_or_default(),
                arg_values: HashMap::new(),
            });
        }
        b"ParameterBlock" => {
            // Begin accumulating a channel parameter block's membership (only the
            // first is retained). A block inside `<Module>`/`<Channel>` describes
            // per-channel com-object membership.
            if !state.dynamic.membership_captured {
                state.dynamic.cur_membership = Some(ChannelMembership::default());
            }
        }
        b"choose" if state.lp.is_some() => {
            // A `<choose>` inside a load procedure guards the ops it holds.
            if let Some(lp) = state.lp.as_mut() {
                lp.chooses.push(LoadChoose {
                    param_ref_id: get(m, b"ParamRefId")
                        .and_then(|id| app_relative_id(id, &app.id))
                        .map(str::to_string)
                        .unwrap_or_default(),
                    tests: Vec::new(),
                });
                state.lp_frames.push((lp.chooses.len() - 1, None));
            }
        }
        b"when" if state.lp.is_some() => {
            if let (Some(lp), Some(frame)) = (state.lp.as_mut(), state.lp_frames.last_mut())
                && let Some(choose) = lp.chooses.get_mut(frame.0)
            {
                choose
                    .tests
                    .push(WhenTest::parse(get(m, b"test"), get(m, b"default")));
                frame.1 = Some(choose.tests.len() - 1);
            }
        }
        b"choose" => {
            // Push a `<choose ParamRefId=…>` conditional group. Nested chooses
            // stack rather than replacing the enclosing one.
            if state.dynamic.cur_membership.is_some() {
                state.dynamic.choose_stack.push(ChooseFrame {
                    group: ConditionalGroup {
                        param_ref_id: get(m, b"ParamRefId")
                            .and_then(|id| app_relative_id(id, &app.id))
                            .map(str::to_string)
                            .unwrap_or_default(),
                        branches: Vec::new(),
                        branches_all: Vec::new(),
                    },
                    when: None,
                });
            }
        }
        b"when" => {
            // Open a `<when>` branch on the innermost `<choose>`; its
            // `<ComObjectRefRef>`s collect into this frame until it closes.
            if let Some(frame) = state.dynamic.choose_stack.last_mut() {
                frame.when = Some(WhenBranch {
                    test: WhenTest::parse(get(m, b"test"), get(m, b"default")),
                    members: Vec::new(),
                });
            }
        }
        // A control op with children (e.g. LdCtrlCompareProp wrapping data).
        name if name.starts_with(b"LdCtrl") => {
            push_load_op(&mut state.lp, e, m);
            record_load_guards(state);
        }
        _ => {}
    }

    // A `<Translation>` may appear as a Start with a nested value; capture attr.
    if e.local_name().as_ref() == b"Translation" {
        translations.record(m, TRANSLATED);
    }
    Ok(())
}

/// Reads the `<Options>` element's attributes into `app`.
fn insert_options(app: &mut ApplicationProgram, m: &Attrs) {
    let flag =
        |name: &[u8]| get(m, name).is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");
    app.download_invisible_parameters = get(m, b"DownloadInvisibleParameters").map(str::to_string);
    app.prefer_partial_download = flag(b"PreferPartialDownloadIfApplicationLoaded");
    app.parameters_little_endian =
        get(m, b"ParameterByteOrder").is_some_and(|v| v.eq_ignore_ascii_case("LittleEndian"));
    app.text_parameter_encoding = get(m, b"TextParameterEncoding").map(str::to_string);
    app.legacy_patch_manufacturer_in_task_segment = flag(b"LegacyPatchManufacturerIdInTaskSegment");
    app.supports_extended_memory_services = flag(b"SupportsExtendedMemoryServices");
}

/// Reads a `<Extension>` element: whether it names an ETS download plugin
/// (the attribute's presence counts, the products leave it empty).
fn insert_extension(app: &mut ApplicationProgram, m: &Attrs) {
    if get(m, b"EtsDownloadPlugin").is_some() {
        app.ets_download_plugin = true;
    }
}

/// Handles an `Empty` (self-closing) event.
fn handle_empty(
    e: &BytesStart,
    context: &str,
    app: &mut ApplicationProgram,
    translations: &mut TranslationCollector,
    attrs: &mut Attrs,
    state: &mut ParseState,
) -> Result<()> {
    attrs.parse_into(e, context)?;
    let m = &*attrs;
    state.tree.empty(e.local_name().as_ref(), m, &app.id);
    match e.local_name().as_ref() {
        b"ComObject" => insert_com_object(app, m),
        b"ComObjectRef" => insert_com_object_ref(app, m),
        b"Channel" => insert_channel(app, m),
        b"Argument" => insert_argument(app, m),
        b"Allocator" => insert_allocator(app, m),
        b"Options" => insert_options(app, m),
        b"Extension" => insert_extension(app, m),
        b"ComObjectTable" => insert_com_object_table(app, m),
        b"NumericArg" => {
            // A `<NumericArg RefId=arg-id Value=n>` of the current `<Module>`.
            if let Some(module) = state.dynamic.cur_module.as_mut()
                && let (Some(arg_id), Some(value)) = (
                    get(m, b"RefId").and_then(|id| app_relative_id(id, &app.id)),
                    get(m, b"Value").and_then(|s| s.parse::<i64>().ok()),
                )
            {
                module.arg_values.insert(arg_id.to_string(), value);
            }
        }
        b"ComObjectRefRef" => {
            // A channel's com-object membership entry. Inside a `<when>` it joins
            // that branch; directly under the parameter block it is unconditional.
            if let Some(ref_id) = get(m, b"RefId").and_then(|id| app_relative_id(id, &app.id)) {
                let ref_id = ref_id.to_string();
                match state.dynamic.open_when() {
                    Some(branch) => branch.members.push(ref_id),
                    None => {
                        if let Some(mem) = state.dynamic.cur_membership.as_mut() {
                            mem.unconditional.push(ref_id);
                        }
                    }
                }
            }
        }
        b"ParameterRefRef" => {
            // A channel's referenced parameter (drives which module params ETS
            // writes for the channel).
            if let Some(mem) = state.dynamic.cur_membership.as_mut()
                && let Some(ref_id) = get(m, b"RefId").and_then(|id| app_relative_id(id, &app.id))
            {
                mem.parameter_refs.push(ref_id.to_string());
            }
        }
        b"Parameter" => {
            // A parameter with no <Memory> child.
            let pid = insert_parameter_start(app, m);
            // A self-closing member `<Parameter>` inside a `<Union>`.
            if let (Some(union), Some(pid)) = (state.union.as_mut(), pid.as_ref()) {
                union.members.push(union_member(pid, m));
            }
        }
        b"ParameterRef" => insert_parameter_ref(app, m),
        b"Memory" => {
            // A union's single `<Memory>` child sets its base location; it always
            // precedes the member `<Parameter>`s, so route it there while the
            // union has no base yet. Otherwise it belongs to the open parameter.
            match state.union.as_mut() {
                Some(union) if union.memory.is_none() => {
                    union.memory = Some(Memory {
                        code_segment: get(m, b"CodeSegment").map(str::to_string),
                        offset: get(m, b"Offset").and_then(|s| s.parse().ok()),
                        bit_offset: get(m, b"BitOffset").and_then(|s| s.parse().ok()),
                        base_offset: get(m, b"BaseOffset").map(str::to_string),
                    });
                }
                _ => attach_memory(app, &state.param_id, m),
            }
        }
        // A parameter whose value lives in an interface-object property
        // (issue #390). A union based on a property is not modelled: its
        // members keep no location.
        b"Property" if state.union.is_none() => attach_property(app, &state.param_id, m),
        b"TranslationElement" => translations.enter_element(get(m, b"RefId")),
        b"Translation" => translations.record(m, TRANSLATED),
        // Parameter-type shapes (all self-closing except TypeRestriction).
        b"TypeNumber" => {
            state.pt_kind = Some(ParameterType::Int {
                size_bits: get(m, b"SizeInBit").and_then(|s| s.parse().ok()),
                min: get(m, b"minInclusive").and_then(|s| s.parse().ok()),
                max: get(m, b"maxInclusive").and_then(|s| s.parse().ok()),
                signed: get(m, b"Type") == Some("signedInt"),
            });
        }
        b"TypeText" => {
            state.pt_kind = Some(ParameterType::Text {
                size_bits: get(m, b"SizeInBit").and_then(|s| s.parse().ok()),
            });
        }
        b"TypeFloat" => {
            state.pt_kind = Some(ParameterType::Float {
                encoding: get(m, b"Encoding").map(str::to_string),
                min: get(m, b"minInclusive").and_then(|s| s.parse().ok()),
                max: get(m, b"maxInclusive").and_then(|s| s.parse().ok()),
            });
        }
        b"TypeNone" => state.pt_kind = Some(ParameterType::None),
        b"Enumeration" => {
            if let Some(ParameterType::Enum { values, .. }) = state.pt_kind.as_mut()
                && let (Some(value), Some(text)) = (
                    get(m, b"Value").and_then(|s| s.parse::<i64>().ok()),
                    get(m, b"Text"),
                )
            {
                let binary_value = get(m, b"BinaryValue").and_then(|b| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(b.trim())
                        .ok()
                });
                values.push(EnumValue {
                    value,
                    text: text.to_string(),
                    default_text: text.to_string(),
                    translations: BTreeMap::new(),
                    id: get(m, b"Id").map(str::to_string),
                    binary_value,
                });
            }
        }
        b"when" if state.lp.is_some() => {
            // A self-closed `<when …/>` in a load procedure holds no op, but
            // its test still counts: a `<when default="true">` sibling is
            // taken only when no test matches (issue #402).
            if let (Some(lp), Some(frame)) = (state.lp.as_mut(), state.lp_frames.last())
                && let Some(choose) = lp.chooses.get_mut(frame.0)
            {
                choose
                    .tests
                    .push(WhenTest::parse(get(m, b"test"), get(m, b"default")));
            }
        }
        b"RelativeSegment" => insert_segment(app, m, SegmentKind::Relative),
        b"AbsoluteSegment" => insert_segment(app, m, SegmentKind::Absolute),
        name if name.starts_with(b"Type") => {
            // A colour of a space the schema names has its own shape (issue
            // #616); any other space stays an `Other`.
            if name == b"TypeColor"
                && let Some(space) = get(m, b"Space").and_then(ColorSpace::from_attr)
            {
                state.pt_kind = Some(ParameterType::Color { space });
                return Ok(());
            }
            // Other type shapes (TypeColor, TypeTime, TypePicture, TypeIPAddress…).
            let kind = String::from_utf8_lossy(name).into_owned();
            state.pt_kind = Some(ParameterType::Other {
                kind,
                size_bits: get(m, b"SizeInBit").and_then(|s| s.parse().ok()),
                unit: get(m, b"Unit").map(str::to_string),
            });
        }
        name if name.starts_with(b"LdCtrl") => {
            push_load_op(&mut state.lp, e, m);
            record_load_guards(state);
        }
        _ => {}
    }
    Ok(())
}

/// The attributes a translation may replace.
const TRANSLATED: &[&str] = &["Name", "Text", "FunctionText", "InitialValue"];

/// Applies the collected translations to names, texts, function texts and
/// enumeration texts.
fn apply_translations(app: &mut ApplicationProgram, translations: &TranslationCollector) {
    if translations.is_empty() {
        return;
    }
    // Application name.
    if let Some(t) = translations.get(&app.id, "Name") {
        app.name = Some(t.to_string());
    }
    for (id, obj) in app.com_objects.iter_mut() {
        if let Some(t) = translations.get(id, "Text") {
            obj.text = Some(t.to_string());
        }
        if let Some(t) = translations.get(id, "FunctionText") {
            obj.function_text = Some(t.to_string());
        }
    }
    for (id, cref) in app.com_object_refs.iter_mut() {
        if let Some(t) = translations.get(id, "Text") {
            cref.text = Some(t.to_string());
        }
        if let Some(t) = translations.get(id, "FunctionText") {
            cref.function_text = Some(t.to_string());
        }
    }
    for decl in app.parameter_types.values_mut() {
        if let ParameterType::Enum { values, .. } = &mut decl.kind {
            for v in values {
                if let Some(t) = v.id.as_deref().and_then(|id| translations.get(id, "Text")) {
                    v.text = t.to_string();
                }
                if let Some(all) = v.id.as_deref().and_then(|id| translations.enum_labels(id)) {
                    v.translations = all.clone();
                }
            }
        }
    }
    for (id, param) in app.parameters.iter_mut() {
        if let Some(t) = translations.get(id, "Text") {
            param.text = Some(t.to_string());
        }
        if let Some(t) = translations.get(id, "InitialValue") {
            param.initial_value = Some(t.to_string());
        }
    }
    for (id, pref) in app.parameter_refs.iter_mut() {
        if let Some(t) = translations.get(id, "Text") {
            pref.text = Some(t.to_string());
        }
    }
    let app_id = app.id.clone();
    let full = |rel: &str| format!("{app_id}_{rel}");
    for (rel, ch) in app.channel_refs.iter_mut() {
        if let Some(t) = translations.get(&full(rel), "Text") {
            ch.text = Some(t.to_string());
        }
    }
    fn translate_tree(
        nodes: &mut [DynamicNode],
        full: &dyn Fn(&str) -> String,
        translations: &TranslationCollector,
    ) {
        for node in nodes {
            match node {
                DynamicNode::Channel {
                    id, text, children, ..
                }
                | DynamicNode::ParameterBlock {
                    id, text, children, ..
                } => {
                    if let Some(t) = translations.get(&full(id), "Text") {
                        *text = Some(t.to_string());
                    }
                    translate_tree(children, full, translations);
                }
                DynamicNode::Choose { whens, .. } => {
                    for w in whens {
                        translate_tree(&mut w.children, full, translations);
                    }
                }
                DynamicNode::Repeat { children, .. } => {
                    translate_tree(children, full, translations);
                }
                DynamicNode::ParameterRefRef(_)
                | DynamicNode::ComObjectRefRef(_)
                | DynamicNode::Module { .. }
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    translate_tree(&mut app.dynamic, &full, translations);
    for body in app.module_dynamics.values_mut() {
        translate_tree(body, &full, translations);
    }
}

/// Records where `<ComObjectTable>` places the group-object table.
fn insert_com_object_table(app: &mut ApplicationProgram, m: &Attrs) {
    if let Some(code_segment) = get(m, b"CodeSegment") {
        app.com_object_table = Some(TableLocation {
            code_segment: code_segment.to_string(),
            offset: get(m, b"Offset")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0),
        });
    }
}

fn insert_com_object(app: &mut ApplicationProgram, m: &Attrs) {
    let Some(id) = get(m, b"Id") else { return };
    let id = id.to_string();
    app.com_objects.insert(
        id.clone(),
        ComObject {
            id,
            number: get(m, b"Number").and_then(|s| s.parse().ok()).unwrap_or(0),
            name: get(m, b"Name").map(str::to_string),
            text: get(m, b"Text").map(str::to_string),
            function_text: get(m, b"FunctionText").map(str::to_string),
            object_size: get(m, b"ObjectSize").map(str::to_string),
            dpt: get(m, b"DatapointType").and_then(parse_ets_dpt),
            flags: flagset_from(m),
            priority: get(m, b"Priority").and_then(bussard_model::Priority::from_ets),
            base_number_ref: get(m, b"BaseNumber").map(str::to_string),
        },
    );
}

fn insert_com_object_ref(app: &mut ApplicationProgram, m: &Attrs) {
    let (Some(id), Some(ref_id)) = (get(m, b"Id"), get(m, b"RefId")) else {
        return;
    };
    let id = id.to_string();
    app.com_object_refs.insert(
        id.clone(),
        ComObjectRef {
            id,
            ref_id: ref_id.to_string(),
            name: get(m, b"Name").map(str::to_string),
            text: get(m, b"Text").map(str::to_string),
            function_text: get(m, b"FunctionText").map(str::to_string),
            object_size: get(m, b"ObjectSize").map(str::to_string),
            dpt: get(m, b"DatapointType").and_then(parse_ets_dpt),
            flags: flagset_from(m),
            priority: get(m, b"Priority").and_then(bussard_model::Priority::from_ets),
            text_parameter_ref: relative_attr(m, b"TextParameterRefId", &app.id),
        },
    );
}

/// An id-valued attribute with the `<app-id>_` prefix stripped (kept verbatim
/// when it lacks the prefix); `None` when absent or empty.
fn relative_attr(m: &Attrs, key: &[u8], app_id: &str) -> Option<String> {
    get(m, key)
        .filter(|s| !s.is_empty())
        .map(|id| app_relative_id(id, app_id).unwrap_or(id).to_string())
}

/// A non-empty string attribute.
fn non_empty_attr(m: &Attrs, key: &[u8]) -> Option<String> {
    get(m, key).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Inserts a Dynamic-section `<Channel>` keyed by its app-relative id.
fn insert_channel(app: &mut ApplicationProgram, m: &Attrs) {
    let Some(id) = get(m, b"Id") else { return };
    let Some(rel) = app_relative_id(id, &app.id) else {
        return;
    };
    app.channels.insert(
        rel.to_string(),
        ChannelDef {
            name: get(m, b"Name")
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            text: get(m, b"Text")
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        },
    );
    app.channel_refs.insert(
        rel.to_string(),
        ChannelRef {
            id: rel.to_string(),
            number: get(m, b"Number").and_then(|s| s.trim().parse().ok()),
            name: non_empty_attr(m, b"Name"),
            text: non_empty_attr(m, b"Text"),
            text_parameter_ref: relative_attr(m, b"TextParameterRefId", &app.id),
        },
    );
}

/// Records a module `<Argument>`'s name → app-relative id (first wins) and
/// its `Allocates`.
fn insert_argument(app: &mut ApplicationProgram, m: &Attrs) {
    let Some(rel) = get(m, b"Id").and_then(|id| app_relative_id(id, &app.id)) else {
        return;
    };
    if let Some(allocates) = get(m, b"Allocates").and_then(|v| v.trim().parse::<i64>().ok()) {
        app.argument_allocates.insert(rel.to_string(), allocates);
    }
    if let Some(name) = get(m, b"Name") {
        app.argument_ids
            .entry(name.to_string())
            .or_insert_with(|| rel.to_string());
    }
}

/// Records an `<Allocator Id Start maxInclusive>` (issue #449).
fn insert_allocator(app: &mut ApplicationProgram, m: &Attrs) {
    let (Some(rel), Some(start)) = (
        get(m, b"Id").and_then(|id| app_relative_id(id, &app.id)),
        get(m, b"Start").and_then(|v| v.trim().parse::<i64>().ok()),
    ) else {
        return;
    };
    let max_inclusive = get(m, b"maxInclusive").and_then(|v| v.trim().parse::<i64>().ok());
    app.allocators.insert(
        rel.to_string(),
        Allocator {
            start,
            max_inclusive,
        },
    );
}

/// Inserts a parameter, returning its id so the caller can attach a later
/// `<Memory>` child to it.
fn insert_parameter_start(app: &mut ApplicationProgram, m: &Attrs) -> Option<String> {
    let id = get(m, b"Id")?.to_string();
    app.parameters.insert(
        id.clone(),
        Parameter {
            id: id.clone(),
            name: get(m, b"Name").map(str::to_string),
            text: get(m, b"Text").map(str::to_string),
            parameter_type: get(m, b"ParameterType").map(str::to_string),
            default: get(m, b"Value").map(str::to_string),
            access: get(m, b"Access").map(str::to_string),
            suffix_text: get(m, b"SuffixText").map(str::to_string),
            memory: None,
            base_value: get(m, b"BaseValue").map(str::to_string),
            property: None,
            legacy_patch_always: get(m, b"LegacyPatchAlways").is_some_and(parse_xml_bool),
            initial_value: get(m, b"InitialValue").map(str::to_string),
        },
    );
    Some(id)
}

/// Builds a [`UnionMember`] from a member `<Parameter>`'s own attributes.
///
/// Union members carry their position as direct `Offset`/`BitOffset` attributes
/// (relative to the union base), not as a `<Memory>` child. The
/// `DefaultUnionParameter` flag (spelled `"1"` or `"true"` in the wild) marks the
/// member whose default value ETS lays into the shared region.
fn union_member(pid: &str, m: &Attrs) -> UnionMember {
    let is_default = matches!(get(m, b"DefaultUnionParameter"), Some("1" | "true"));
    UnionMember {
        parameter: pid.to_string(),
        offset: get(m, b"Offset").and_then(|s| s.parse().ok()),
        bit_offset: get(m, b"BitOffset").and_then(|s| s.parse().ok()),
        is_default,
    }
}

fn attach_memory(app: &mut ApplicationProgram, cur_param_id: &Option<String>, m: &Attrs) {
    let Some(pid) = cur_param_id else {
        return;
    };
    if let Some(param) = app.parameters.get_mut(pid) {
        param.memory = Some(Memory {
            code_segment: get(m, b"CodeSegment").map(str::to_string),
            offset: get(m, b"Offset").and_then(|s| s.parse().ok()),
            bit_offset: get(m, b"BitOffset").and_then(|s| s.parse().ok()),
            base_offset: get(m, b"BaseOffset").map(str::to_string),
        });
    }
}

fn attach_property(app: &mut ApplicationProgram, cur_param_id: &Option<String>, m: &Attrs) {
    let Some(pid) = cur_param_id else {
        return;
    };
    let Some(property_id) = get(m, b"PropertyId").and_then(|s| s.parse().ok()) else {
        return;
    };
    if let Some(param) = app.parameters.get_mut(pid) {
        param.property = Some(PropertyLocation {
            object_index: get(m, b"ObjectIndex").and_then(|s| s.parse().ok()),
            object_type: get(m, b"ObjectType").and_then(|s| s.parse().ok()),
            occurrence: get(m, b"Occurrence").and_then(|s| s.parse().ok()),
            property_id,
            offset: get(m, b"Offset").and_then(|s| s.parse().ok()).unwrap_or(0),
            bit_offset: get(m, b"BitOffset")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        });
    }
}

fn insert_parameter_ref(app: &mut ApplicationProgram, m: &Attrs) {
    let (Some(id), Some(ref_id)) = (get(m, b"Id"), get(m, b"RefId")) else {
        return;
    };
    let id = id.to_string();
    app.parameter_refs.insert(
        id.clone(),
        ParameterRef {
            id,
            ref_id: ref_id.to_string(),
            value: get(m, b"Value").map(str::to_string),
            access: get(m, b"Access").map(str::to_string),
            text: get(m, b"Text").map(str::to_string),
        },
    );
}

fn insert_segment(app: &mut ApplicationProgram, m: &Attrs, kind: SegmentKind) {
    let Some(id) = get(m, b"Id") else { return };
    let id = id.to_string();
    let address_or_offset = match kind {
        SegmentKind::Relative => get(m, b"Offset").and_then(|s| s.parse().ok()),
        SegmentKind::Absolute => get(m, b"Address").and_then(|s| s.parse().ok()),
    };
    app.code_segments.insert(
        id.clone(),
        CodeSegment {
            id,
            kind,
            size: get(m, b"Size").and_then(|s| s.parse().ok()),
            address_or_offset,
            load_state_machine: get(m, b"LoadStateMachine").and_then(|s| s.parse().ok()),
            // Filled later if a `<Data>`/`<Mask>` child follows; a self-closing
            // segment stays metadata-only.
            data: None,
            mask: None,
        },
    );
}

/// Everything the streaming element handlers accumulate between events.
///
/// The parser is a flat `quick-xml` event loop, so an element that is only
/// complete once its children have been seen (a `<ParameterType>` and its shape,
/// a `<LoadProcedure>` and its ops, a `<Parameter>` and its `<Memory>`, a
/// `<Union>` and its members, the Dynamic section's modules and channel
/// membership) parks its half-built value here. Grouping them in one struct is
/// what keeps `handle_start`/`handle_empty` down to six parameters instead of
/// twelve — they used to carry an unjustified
/// `#[allow(clippy::too_many_arguments)]` each.
#[derive(Debug, Default)]
struct ParseState {
    /// The `Id` of the `<ParameterType>` currently being built (the element
    /// wraps one shape element, sometimes with child `<Enumeration>`s).
    pt_id: Option<String>,
    /// That parameter type's `Name`.
    pt_name: Option<String>,
    /// That parameter type's shape, once its child element has been seen.
    pt_kind: Option<ParameterType>,
    /// The `<LoadProcedure>` currently being built.
    lp: Option<LoadProcedure>,
    /// The `<choose>`s open inside that procedure, outermost first: the
    /// choose's index and the `<when>` branch open in it.
    lp_frames: Vec<(usize, Option<usize>)>,
    /// The `<Parameter>` whose `<Memory>` child we are waiting for.
    param_id: Option<String>,
    /// The `<Union>` currently being built. Its single `<Memory>` child gives the
    /// shared base location; member `<Parameter>`s that follow carry
    /// union-relative `Offset`/`BitOffset` attributes.
    union: Option<Union>,
    /// Dynamic-section module-instance / channel-membership accumulation.
    dynamic: DynamicState,
    /// The Dynamic-section tree being built (see [`DynamicNode`]).
    tree: DynTreeBuilder,
}

/// Builds the [`DynamicNode`] trees of the application's Dynamic section and of
/// each `<ModuleDef>`'s Dynamic section from streaming events.
#[derive(Debug, Default)]
struct DynTreeBuilder {
    /// The app-relative ids of the open `<ModuleDef>`s, outermost first: a
    /// `<SubModuleDefs>` nests one module definition in another (issue
    /// #449), and the outer definition's `<Dynamic>` follows the inner ones.
    module_defs: Vec<String>,
    /// The open frames, outermost first; non-empty exactly while inside a
    /// `<Dynamic>` element.
    frames: Vec<DynFrame>,
}

/// One open element of the Dynamic tree under construction.
#[derive(Debug)]
enum DynFrame {
    /// The `<Dynamic>` element itself.
    Root(Vec<DynamicNode>),
    /// An open `<choose>`.
    Choose {
        param_ref_id: String,
        whens: Vec<DynamicWhen>,
    },
    /// An open `<when>`.
    When(DynamicWhen),
    /// An open `<Module>` collecting its `<NumericArg>`s.
    Module {
        id: String,
        module_def: String,
        args: HashMap<String, i64>,
        computed_args: Vec<ComputedArg>,
    },
    /// An open `<Repeat>` and its children so far.
    Repeat {
        id: String,
        param_ref_id: Option<String>,
        count: Option<u32>,
        children: Vec<DynamicNode>,
    },
    /// An open `<Channel>` and its children so far.
    Channel(ChannelRef, Vec<DynamicNode>),
    /// An open `<ParameterBlock>` and its children so far.
    Block(BlockRef, Vec<DynamicNode>),
}

impl DynTreeBuilder {
    /// Appends a finished node to the innermost frame that holds children.
    fn push_node(&mut self, node: DynamicNode) {
        match self.frames.last_mut() {
            Some(DynFrame::Root(children))
            | Some(DynFrame::When(DynamicWhen { children, .. }))
            | Some(DynFrame::Channel(_, children))
            | Some(DynFrame::Block(_, children))
            | Some(DynFrame::Repeat { children, .. }) => {
                children.push(node);
            }
            // A node directly under `<choose>` or `<Module>` is not valid
            // schema; drop it rather than guess where it belongs.
            _ => {}
        }
    }

    /// A leaf element (`ParameterRefRef`, `ComObjectRefRef`, `Assign`), whether
    /// it arrived as a start or an empty event. Returns whether it was one.
    fn leaf(&mut self, name: &[u8], m: &Attrs, app_id: &str) -> bool {
        let rel = |key: &[u8]| {
            get(m, key).map(|id| app_relative_id(id, app_id).unwrap_or(id).to_string())
        };
        let node = match name {
            b"ParameterRefRef" => rel(b"RefId").map(DynamicNode::ParameterRefRef),
            b"ComObjectRefRef" => rel(b"RefId").map(DynamicNode::ComObjectRefRef),
            b"Assign" => rel(b"TargetParamRefRef").map(|target| DynamicNode::Assign {
                target,
                source: rel(b"SourceParamRefRef"),
                value: get(m, b"Value").map(str::to_string),
            }),
            _ => return false,
        };
        if let Some(node) = node {
            self.push_node(node);
        }
        true
    }

    /// A start event.
    fn start(&mut self, name: &[u8], m: &Attrs, app_id: &str) {
        let rel = |key: &[u8]| {
            get(m, key)
                .map(|id| app_relative_id(id, app_id).unwrap_or(id).to_string())
                .unwrap_or_default()
        };
        if self.frames.is_empty() {
            match name {
                b"ModuleDef" => self.module_defs.push(rel(b"Id")),
                b"Dynamic" => self.frames.push(DynFrame::Root(Vec::new())),
                _ => {}
            }
            return;
        }
        match name {
            b"choose" => self.frames.push(DynFrame::Choose {
                param_ref_id: rel(b"ParamRefId"),
                whens: Vec::new(),
            }),
            b"when" => self.frames.push(DynFrame::When(DynamicWhen {
                test: WhenTest::parse(get(m, b"test"), get(m, b"default")),
                children: Vec::new(),
            })),
            b"Module" => self.frames.push(DynFrame::Module {
                id: rel(b"Id"),
                module_def: rel(b"RefId"),
                args: HashMap::new(),
                computed_args: Vec::new(),
            }),
            b"Repeat" => self.frames.push(DynFrame::Repeat {
                id: rel(b"Id"),
                param_ref_id: relative_attr(m, b"ParameterRefId", app_id),
                count: get(m, b"Count").and_then(|v| v.trim().parse().ok()),
                children: Vec::new(),
            }),
            b"Channel" => self.frames.push(DynFrame::Channel(
                ChannelRef {
                    id: rel(b"Id"),
                    number: get(m, b"Number").and_then(|s| s.trim().parse().ok()),
                    name: non_empty_attr(m, b"Name"),
                    text: non_empty_attr(m, b"Text"),
                    text_parameter_ref: relative_attr(m, b"TextParameterRefId", app_id),
                },
                Vec::new(),
            )),
            b"ParameterBlock" => self.frames.push(DynFrame::Block(
                BlockRef {
                    id: rel(b"Id"),
                    name: non_empty_attr(m, b"Name"),
                    text: non_empty_attr(m, b"Text"),
                    text_parameter_ref: relative_attr(m, b"TextParameterRefId", app_id),
                    param_ref: relative_attr(m, b"ParamRefId", app_id),
                },
                Vec::new(),
            )),
            _ => {
                self.leaf(name, m, app_id);
            }
        }
    }

    /// An empty (self-closing) event.
    fn empty(&mut self, name: &[u8], m: &Attrs, app_id: &str) {
        if self.frames.is_empty() {
            return;
        }
        match name {
            b"NumericArg" => {
                let rel = |key: &[u8]| {
                    get(m, key).map(|id| app_relative_id(id, app_id).unwrap_or(id).to_string())
                };
                if let Some(DynFrame::Module {
                    args,
                    computed_args,
                    ..
                }) = self.frames.last_mut()
                    && let Some(arg) = rel(b"RefId")
                {
                    let value = get(m, b"Value").and_then(|v| v.trim().parse::<i64>().ok());
                    let allocator = rel(b"AllocatorRefId");
                    let base = rel(b"BaseValue");
                    match (value, &allocator, &base) {
                        (Some(value), None, None) => {
                            args.insert(arg, value);
                        }
                        // An allocator or a base makes the value the
                        // instance's to compute (issue #449); a bare
                        // argument without a value stays absent.
                        (_, Some(_), _) | (_, _, Some(_)) => computed_args.push(ComputedArg {
                            arg,
                            allocator,
                            value,
                            base,
                        }),
                        (None, None, None) => {}
                    }
                }
            }
            b"when" | b"choose" | b"Module" | b"Channel" | b"ParameterBlock" | b"Repeat" => {
                // An empty branch, choose, argument-less module or empty
                // container: open and close it at once.
                self.start(name, m, app_id);
                self.end(name, None);
            }
            _ => {
                self.leaf(name, m, app_id);
            }
        }
    }

    /// An end event. `app` receives a finished `<Dynamic>` tree.
    fn end(&mut self, name: &[u8], app: Option<&mut ApplicationProgram>) {
        match name {
            b"ModuleDef" if self.frames.is_empty() => {
                self.module_defs.pop();
            }
            b"when" => {
                if let Some(DynFrame::When(_)) = self.frames.last()
                    && let Some(DynFrame::When(branch)) = self.frames.pop()
                    && let Some(DynFrame::Choose { whens, .. }) = self.frames.last_mut()
                {
                    whens.push(branch);
                }
            }
            b"choose" => {
                if let Some(DynFrame::Choose { .. }) = self.frames.last()
                    && let Some(DynFrame::Choose {
                        param_ref_id,
                        whens,
                    }) = self.frames.pop()
                {
                    self.push_node(DynamicNode::Choose {
                        param_ref_id,
                        whens,
                    });
                }
            }
            b"Module" => {
                if let Some(DynFrame::Module { .. }) = self.frames.last()
                    && let Some(DynFrame::Module {
                        id,
                        module_def,
                        args,
                        computed_args,
                    }) = self.frames.pop()
                {
                    self.push_node(DynamicNode::Module {
                        id,
                        module_def,
                        args,
                        computed_args,
                    });
                }
            }
            b"Repeat" => {
                if let Some(DynFrame::Repeat { .. }) = self.frames.last()
                    && let Some(DynFrame::Repeat {
                        id,
                        param_ref_id,
                        count,
                        children,
                    }) = self.frames.pop()
                    && !children.is_empty()
                {
                    self.push_node(DynamicNode::Repeat {
                        id,
                        param_ref_id,
                        count,
                        children,
                    });
                }
            }
            b"Channel" => {
                if let Some(DynFrame::Channel(..)) = self.frames.last()
                    && let Some(DynFrame::Channel(ch, children)) = self.frames.pop()
                    && !children.is_empty()
                {
                    self.push_node(DynamicNode::Channel {
                        id: ch.id,
                        name: ch.name,
                        text: ch.text,
                        number: ch.number,
                        text_parameter_ref: ch.text_parameter_ref,
                        children,
                    });
                }
            }
            b"ParameterBlock" => {
                if let Some(DynFrame::Block(..)) = self.frames.last()
                    && let Some(DynFrame::Block(block, children)) = self.frames.pop()
                    && !children.is_empty()
                {
                    self.push_node(DynamicNode::ParameterBlock {
                        id: block.id,
                        name: block.name,
                        text: block.text,
                        text_parameter_ref: block.text_parameter_ref,
                        param_ref: block.param_ref,
                        children,
                    });
                }
            }
            b"Dynamic" => {
                // Unwind whatever malformed XML left open, then store the root.
                while self.frames.len() > 1 {
                    self.frames.pop();
                }
                if let (Some(DynFrame::Root(children)), Some(app)) = (self.frames.pop(), app) {
                    match self.module_defs.last() {
                        Some(md) => {
                            app.module_dynamics.insert(md.clone(), children);
                        }
                        None => app.dynamic = children,
                    }
                }
                self.frames.clear();
            }
            _ => {}
        }
    }
}

/// Mutable state for parsing the Dynamic section's module instances and channel
/// membership across streaming events.
///
/// The parser accumulates a `<Module>`'s `<NumericArg>`s until the module
/// closes, and a channel `<ParameterBlock>`'s `<ComObjectRefRef>`s /
/// `<ParameterRefRef>`s / `<choose>` branches until the block closes. Keeping
/// this in one struct avoids threading a handful of extra parameters through the
/// already-wide `handle_start`/`handle_empty` signatures.
#[derive(Debug, Default)]
struct DynamicState {
    /// The `<Module>` instance being accumulated (its arg values), if inside one.
    cur_module: Option<ModuleInstance>,
    /// The channel `<ParameterBlock>` membership being accumulated, if inside one.
    cur_membership: Option<ChannelMembership>,
    /// The open `<choose>` elements, outermost first.
    ///
    /// A `<choose>` nested inside a `<when>` is ubiquitous in real Dynamic
    /// sections. With a single slot the inner group overwrote the outer one, the
    /// inner `</when>` took the outer branch's collected refs, and the outer
    /// `</choose>` then found nothing to attach — silently mis-attributing
    /// conditional com-objects. A stack keeps each frame's refs its own.
    choose_stack: Vec<ChooseFrame>,
    /// Whether the application already captured a channel membership (only the
    /// first module channel is captured — a module template has one channel).
    membership_captured: bool,
}

/// One open `<choose>` element and, while inside one, its open `<when>` branch.
#[derive(Debug)]
struct ChooseFrame {
    /// The group being accumulated.
    group: ConditionalGroup,
    /// The `<when>` branch currently open inside this `<choose>`, if any.
    when: Option<WhenBranch>,
}

impl DynamicState {
    /// The innermost open `<when>` branch, if the parser is inside one.
    fn open_when(&mut self) -> Option<&mut WhenBranch> {
        self.choose_stack.last_mut()?.when.as_mut()
    }
}

/// Which inline binary child of a code segment is currently being buffered.
#[derive(Debug, Clone, Copy)]
enum SegField {
    /// `<Data>`: the segment image bytes.
    Data,
    /// `<Mask>`: the per-byte ownership mask.
    Mask,
}

impl SegField {
    /// The XML element name of this field, for error messages.
    fn as_str(self) -> &'static str {
        match self {
            SegField::Data => "Data",
            SegField::Mask => "Mask",
        }
    }
}

/// Decodes a base64 segment payload (whitespace tolerated), erroring with the
/// segment id and field (`Data`/`Mask`) in context so a corrupt file names the
/// offending segment and which child carried the bad payload.
fn decode_segment_base64(
    raw: &str,
    context: &str,
    seg_id: &str,
    field: SegField,
) -> Result<Vec<u8>> {
    use base64::Engine as _;
    // ETS emits the payload as a single unbroken base64 run, but tolerate stray
    // whitespace defensively rather than fail a whole file over it.
    let trimmed: String = raw.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(trimmed.as_bytes())
        .map_err(|source| EtsError::SegmentDecode {
            context: context.to_string(),
            segment: seg_id.to_string(),
            field: field.as_str(),
            source,
        })
}

/// Decodes an even-length hex byte string (as ETS writes `InlineData`/`Mask`,
/// e.g. `"00000001620100000000"`) into bytes. Returns `None` on odd length or a
/// non-hex digit, or for an empty string, so a malformed value falls back to
/// leaving the field unset rather than mis-decoding.
fn decode_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Decodes a `LdCtrlRelSegment`'s fill attributes into the record's `Mode` and
/// `Fill` octets.
///
/// The KNX schema spells the allocation's fill as `Mode` (bit 0 pre-fills the
/// freshly allocated segment) plus `Fill` (the fill byte). Both are copied as
/// given: a Jung F50 procedure reads `Mode="1" Fill="0"` and ETS sends
/// `03 0b 00 00 18 08 01 00 00 00` (issue #123); `syn-relseg-fill` reads
/// `Mode="0" Fill="255"` and ETS sends `03 0b 00 00 01 00 00 ff 00 00`
/// (issue #480). A value that does not parse as an octet is `0`.
///
/// Without a `Mode` attribute the older reading applies: `Fill="1"`/`"true"` is
/// the flag and `FillByte` the byte (decimal or `0x` hex, default `0`). No
/// attribute at all is [`SegmentFill::NONE`] (the DA.tp shape).
fn parse_fill(m: &Attrs) -> SegmentFill {
    let byte = |raw: Option<&str>| {
        raw.and_then(|s| {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).ok()
            } else {
                s.parse::<u8>().ok()
            }
        })
        .unwrap_or(0)
    };
    if let Some(mode) = get(m, b"Mode") {
        return SegmentFill {
            mode: byte(Some(mode)),
            fill: byte(get(m, b"Fill")),
        };
    }
    let Some(raw) = get(m, b"Fill") else {
        return SegmentFill::NONE;
    };
    let on = matches!(raw.trim(), "1" | "true" | "True" | "TRUE");
    SegmentFill {
        mode: u8::from(on),
        fill: byte(get(m, b"FillByte")),
    }
}

/// Records the branches the op just appended to the open procedure sits in,
/// keeping [`LoadProcedure::guards`] parallel to its ops once any `<choose>`
/// was seen.
fn record_load_guards(state: &mut ParseState) {
    let Some(lp) = state.lp.as_mut() else {
        return;
    };
    if lp.chooses.is_empty() {
        return;
    }
    let guards: Vec<LoadGuard> = state
        .lp_frames
        .iter()
        .filter_map(|(choose, branch)| {
            branch.map(|branch| LoadGuard {
                choose: *choose,
                branch,
            })
        })
        .collect();
    let before = lp.ops.len().saturating_sub(1);
    lp.guards.resize(before, Vec::new());
    lp.guards.push(guards);
}

/// Parses one `LdCtrl*` element into a typed [`LoadOp`], appending to the
/// current load procedure (if any).
pub(crate) fn push_load_op(cur_lp: &mut Option<LoadProcedure>, e: &BytesStart, m: &Attrs) {
    let Some(lp) = cur_lp.as_mut() else {
        return;
    };
    let u = |k: &[u8]| get(m, k).and_then(|s| s.parse::<u32>().ok());
    let s = |k: &[u8]| get(m, k).map(str::to_string);
    let op = match e.local_name().as_ref() {
        b"LdCtrlConnect" => LoadOp::Connect,
        b"LdCtrlDisconnect" => LoadOp::Disconnect,
        b"LdCtrlRestart" => LoadOp::Restart,
        b"LdCtrlMerge" => LoadOp::Merge {
            merge_id: s(b"MergeId"),
        },
        b"LdCtrlMasterReset" => LoadOp::MasterReset {
            erase_code: u(b"EraseCode"),
            channel_number: u(b"ChannelNumber"),
        },
        b"LdCtrlUnload" => LoadOp::Unload {
            lsm_idx: u(b"LsmIdx"),
        },
        b"LdCtrlLoad" => LoadOp::Load {
            lsm_idx: u(b"LsmIdx"),
        },
        b"LdCtrlLoadCompleted" => LoadOp::LoadCompleted {
            lsm_idx: u(b"LsmIdx"),
        },
        b"LdCtrlTaskSegment" => LoadOp::TaskSegment {
            lsm_idx: u(b"LsmIdx"),
            address: u(b"Address"),
        },
        b"LdCtrlTaskCtrl1" => LoadOp::TaskCtrl1 {
            lsm_idx: u(b"LsmIdx"),
            address: u(b"Address"),
            count: u(b"Count"),
        },
        b"LdCtrlTaskPtr" => LoadOp::TaskPtr {
            lsm_idx: u(b"LsmIdx"),
            init_ptr: u(b"InitPtr"),
            save_ptr: u(b"SavePtr"),
            serial_ptr: u(b"SerialPtr"),
        },
        b"LdCtrlTaskCtrl2" => LoadOp::TaskCtrl2 {
            lsm_idx: u(b"LsmIdx"),
            callback: u(b"Callback"),
            address: u(b"Address"),
            seg0: u(b"Seg0"),
            seg1: u(b"Seg1"),
        },
        b"LdCtrlRelSegment" => LoadOp::RelSegment {
            lsm_idx: u(b"LsmIdx"),
            size: u(b"Size"),
            applies_to: s(b"AppliesTo"),
            fill: parse_fill(m),
        },
        b"LdCtrlAbsSegment" => LoadOp::AbsSegment {
            lsm_idx: u(b"LsmIdx"),
            address: u(b"Address"),
            size: u(b"Size"),
            access: u(b"Access"),
            mem_type: u(b"MemType"),
            seg_flags: u(b"SegFlags"),
            seg_type: u(b"SegType"),
        },
        b"LdCtrlWriteRelMem" => LoadOp::WriteRelMem {
            obj_idx: u(b"ObjIdx"),
            offset: u(b"Offset"),
            size: u(b"Size"),
            applies_to: s(b"AppliesTo"),
        },
        b"LdCtrlWriteMem" => LoadOp::WriteMem {
            address: u(b"Address"),
            size: u(b"Size"),
        },
        b"LdCtrlWriteProp" => LoadOp::WriteProp {
            obj_idx: u(b"ObjIdx"),
            obj_type: u(b"ObjType"),
            prop_id: u(b"PropId"),
            inline_data: get(m, b"InlineData").and_then(decode_hex_bytes),
            start_element: u(b"StartElement"),
            count: u(b"Count"),
            verify: get(m, b"Verify").map(parse_xml_bool),
            occurrence: u(b"Occurrence"),
        },
        b"LdCtrlCompareProp" => LoadOp::CompareProp {
            obj_idx: u(b"ObjIdx"),
            obj_type: u(b"ObjType"),
            prop_id: u(b"PropId"),
            inline_data: get(m, b"InlineData").and_then(decode_hex_bytes),
            mask: get(m, b"Mask").and_then(decode_hex_bytes),
            range: s(b"Range"),
            occurrence: u(b"Occurrence"),
            start_element: u(b"StartElement"),
        },
        b"LdCtrlCompareRelMem" => LoadOp::CompareRelMem {
            obj_idx: u(b"ObjIdx"),
            offset: u(b"Offset"),
            size: u(b"Size"),
            inline_data: get(m, b"InlineData").and_then(decode_hex_bytes),
            mask: get(m, b"Mask").and_then(decode_hex_bytes),
            // `Invert` is an ETS boolean attribute; only an explicit "true"
            // (case-insensitive) or "1" inverts the sense, everything else (absent,
            // "false", "0") keeps the default exact-match comparison.
            invert: get(m, b"Invert")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1"))
                .unwrap_or(false),
        },
        b"LdCtrlLoadImageProp" => LoadOp::LoadImageProp {
            obj_idx: u(b"ObjIdx"),
            obj_type: u(b"ObjType"),
            occurrence: u(b"Occurrence"),
            prop_id: u(b"PropId"),
            count: u(b"Count"),
        },
        b"LdCtrlMapError" => LoadOp::MapError {
            original_error: get(m, b"OriginalError").and_then(parse_error_code),
            mapped_error: get(m, b"MappedError").and_then(parse_error_code),
        },
        other => LoadOp::Raw {
            name: String::from_utf8_lossy(other).into_owned(),
            attrs: ordered_attrs(m),
        },
    };
    // Keep the scopes parallel to the ops, whatever pushed ops before.
    lp.applies_to.resize(lp.ops.len(), None);
    lp.applies_to.push(s(b"AppliesTo"));
    lp.ops.push(op);
}

/// An ETS error code attribute: decimal as the corpus writes it
/// (`OriginalError="3221498632"`), or hexadecimal with a `0x` prefix.
fn parse_error_code(v: &str) -> Option<u32> {
    let v = v.trim();
    match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => v.parse::<u32>().ok(),
    }
}

/// An XML schema boolean (`true`/`1` are true, everything else false).
fn parse_xml_bool(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1")
}

/// Returns the attribute map as sorted `(key, value)` pairs for a stable `Raw`.
fn ordered_attrs(m: &Attrs) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = m
        .iter()
        .map(|(k, v)| (String::from_utf8_lossy(k).into_owned(), v.to_string()))
        .collect();
    pairs.sort();
    pairs
}

/// Strips the `<app-id>_` prefix from a fully-qualified element id, returning the
/// app-relative remainder (e.g. `<app>_MD-1_CH-13` → `MD-1_CH-13`). Returns
/// `None` if the id does not carry the app prefix.
fn app_relative_id<'a>(id: &'a str, app_id: &str) -> Option<&'a str> {
    id.strip_prefix(app_id)?.strip_prefix('_')
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fabricated ApplicationProgram exercising every ParameterType, a
    // ParameterRef override, com-object DPT/flag resolution, a code segment,
    // and every typed LoadProcedure variant plus a Raw fallback.
    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
  <ApplicationProgram Id="M-00FA_A-1" ApplicationNumber="7" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Sample" LoadProcedureStyle="MergedProcedure">
   <Static>
    <Code>
     <RelativeSegment Id="M-00FA_A-1_RS-4" Size="10" LoadStateMachine="4" Offset="0"><Data>AAAAAAAAAAAAAA==</Data><Mask>////////////////</Mask></RelativeSegment>
     <AbsoluteSegment Id="M-00FA_A-1_AS-1" Size="256" Address="16384" />
    </Code>
    <ComObjectTable>
     <ComObject Id="M-00FA_A-1_O-0" Number="0" Name="Switch" Text="Switch" FunctionText="On/Off" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" TransmitFlag="Enabled" ReadFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
     <ComObject Id="M-00FA_A-1_O-1" Number="1" Name="Val" Text="Value" ObjectSize="2 Bytes" CommunicationFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-00FA_A-1_O-0_R-1" RefId="M-00FA_A-1_O-0" DatapointType="DPST-1-1" ReadFlag="Enabled" />
     <ComObjectRef Id="M-00FA_A-1_O-1_R-1" RefId="M-00FA_A-1_O-1" DatapointType="DPST-9-1" />
    </ComObjectRefs>
    <ParameterTypes>
     <ParameterType Id="M-00FA_A-1_PT-int" Name="anint"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="100" /></ParameterType>
     <ParameterType Id="M-00FA_A-1_PT-sint" Name="asint"><TypeNumber SizeInBit="8" Type="signedInt" minInclusive="-5" maxInclusive="5" /></ParameterType>
     <ParameterType Id="M-00FA_A-1_PT-enum" Name="anenum"><TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Off" Value="0" Id="e0" /><Enumeration Text="On" Value="1" Id="e1" /></TypeRestriction></ParameterType>
     <ParameterType Id="M-00FA_A-1_PT-txt" Name="atext"><TypeText SizeInBit="112" /></ParameterType>
     <ParameterType Id="M-00FA_A-1_PT-flt" Name="afloat"><TypeFloat Encoding="DPT 9" minInclusive="-10" maxInclusive="10" /></ParameterType>
     <ParameterType Id="M-00FA_A-1_PT-none" Name="anone"><TypeNone /></ParameterType>
     <ParameterType Id="M-00FA_A-1_PT-col" Name="acolor"><TypeColor Space="RGB" /></ParameterType>
    </ParameterTypes>
    <Parameters>
     <Parameter Id="M-00FA_A-1_P-1" Name="Threshold" Text="Threshold" ParameterType="M-00FA_A-1_PT-int" Value="50" Access="ReadWrite"><Memory CodeSegment="M-00FA_A-1_RS-4" Offset="3" BitOffset="2" /></Parameter>
     <Parameter Id="M-00FA_A-1_P-2" Name="Mode" ParameterType="M-00FA_A-1_PT-enum" Value="0" />
    </Parameters>
    <ParameterRefs>
     <ParameterRef Id="M-00FA_A-1_P-1_R-1" RefId="M-00FA_A-1_P-1" Value="75" />
     <ParameterRef Id="M-00FA_A-1_P-2_R-1" RefId="M-00FA_A-1_P-2" Access="None" />
    </ParameterRefs>
   </Static>
   <LoadProcedures>
    <LoadProcedure MergeId="1">
     <LdCtrlConnect />
     <LdCtrlUnload LsmIdx="1" />
     <LdCtrlLoad LsmIdx="2" />
     <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
     <LdCtrlTaskCtrl1 LsmIdx="3" Address="19385" Count="1" />
     <LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="19155" />
     <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="511" />
     <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="5" Offset="0" Size="10" Verify="true" />
     <LdCtrlWriteProp ObjType="11" PropId="204" />
     <LdCtrlLoadCompleted LsmIdx="1" />
     <LdCtrlRestart />
     <LdCtrlDisconnect />
     <LdCtrlLoadImageProp ObjIdx="5" PropId="27" />
    </LoadProcedure>
   </LoadProcedures>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    fn sample() -> std::result::Result<ApplicationProgram, Box<dyn std::error::Error>> {
        Ok(parse_application_program_str("M-00FA_A-1", SAMPLE)?)
    }

    /// Three com-objects: base `High` overridden to `Low` by its ref, base
    /// `Alert` kept by a ref that declares none, and one declaring nothing.
    const PRIORITY_SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
  <ApplicationProgram Id="M-00FA_A-2" ApplicationNumber="8" ApplicationVersion="16" MaskVersion="MV-07B0" Name="Prio">
   <Static>
    <ComObjectTable>
     <ComObject Id="M-00FA_A-2_O-0" Number="0" Text="a" ObjectSize="1 Bit" Priority="High" CommunicationFlag="Enabled" />
     <ComObject Id="M-00FA_A-2_O-1" Number="1" Text="b" ObjectSize="1 Bit" Priority="Alert" CommunicationFlag="Enabled" />
     <ComObject Id="M-00FA_A-2_O-2" Number="2" Text="c" ObjectSize="1 Bit" CommunicationFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-00FA_A-2_O-0_R-1" RefId="M-00FA_A-2_O-0" Priority="Low" />
     <ComObjectRef Id="M-00FA_A-2_O-1_R-1" RefId="M-00FA_A-2_O-1" />
     <ComObjectRef Id="M-00FA_A-2_O-2_R-1" RefId="M-00FA_A-2_O-2" />
    </ComObjectRefs>
   </Static>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn test_insert_com_object_ref_priority_overrides_base()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use bussard_model::Priority;
        let app = parse_application_program_str("M-00FA_A-2", PRIORITY_SAMPLE)?;
        let base = app.com_objects.get("M-00FA_A-2_O-0").ok_or("missing O-0")?;
        assert_eq!(base.priority, Some(Priority::High));
        let resolved: Vec<(u16, Option<Priority>, Priority)> = app
            .resolved_com_objects()
            .iter()
            .map(|c| (c.number(), c.declared_priority(), c.priority()))
            .collect();
        assert_eq!(
            resolved,
            vec![
                (0, Some(Priority::Low), Priority::Low),
                (1, Some(Priority::Alarm), Priority::Alarm),
                (2, None, Priority::Low),
            ]
        );
        Ok(())
    }

    #[test]
    fn parses_identity_and_schema() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = sample()?;
        assert_eq!(app.application_number, Some(7));
        assert_eq!(app.application_version, Some(17));
        assert_eq!(app.version.as_deref(), Some("17"));
        assert_eq!(app.mask_version.as_deref(), Some("07B0"));
        assert_eq!(app.name.as_deref(), Some("Sample"));
        assert_eq!(app.load_procedure_style.as_deref(), Some("MergedProcedure"));
        assert_eq!(app.schema_version.as_deref(), Some("23"));
        Ok(())
    }

    /// `<Options>` decides whether a download writes hidden parameters
    /// (issue #89): only when it declares neither `DownloadInvisibleParameters`
    /// nor a preferred partial download.
    /// `<Options TextParameterEncoding>` names the code page of the text
    /// parameters (issue #401).
    #[test]
    fn test_parse_application_program_text_parameter_encoding() -> Result<()> {
        let xml = |options: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t"><Static>{options}</Static></ApplicationProgram></KNX>"#
            )
        };
        let app = parse_application_program_str(
            "M-1_A-1",
            &xml(r#"<Options TextParameterEncoding="iso-8859-15" />"#),
        )?;
        assert_eq!(app.text_parameter_encoding.as_deref(), Some("iso-8859-15"));
        let app = parse_application_program_str("M-1_A-1", &xml(r#"<Options />"#))?;
        assert_eq!(app.text_parameter_encoding, None);
        Ok(())
    }

    #[test]
    fn test_parse_application_program_download_invisible_parameters() -> Result<()> {
        let xml = |options: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t" MaskVersion="MV-07B0"><Static>{options}</Static></ApplicationProgram></KNX>"#
            )
        };
        for (options, declared, partial, writes) in [
            (r#"<Options Comparable="false" />"#, None, false, true),
            ("", None, false, true),
            (
                r#"<Options DownloadInvisibleParameters="None" />"#,
                Some("None"),
                false,
                false,
            ),
            (
                r#"<Options DownloadInvisibleParameters="Background" PreferPartialDownloadIfApplicationLoaded="true" />"#,
                Some("Background"),
                true,
                false,
            ),
            (
                r#"<Options PreferPartialDownloadIfApplicationLoaded="true"></Options>"#,
                None,
                true,
                false,
            ),
        ] {
            let app = parse_application_program_str("M-1_A-1", &xml(options))?;
            assert_eq!(
                app.download_invisible_parameters.as_deref(),
                declared,
                "{options}"
            );
            assert_eq!(app.prefer_partial_download, partial, "{options}");
            assert_eq!(app.downloads_invisible_parameters(), writes, "{options}");
        }
        Ok(())
    }

    /// Issue #448: without the attributes, a System B program writes hidden
    /// defaults at every schema, a System 7 one from project/21 on; another
    /// mask never does.
    #[test]
    fn test_downloads_invisible_parameters_by_system_and_schema() -> Result<()> {
        for (mask, schema, writes) in [
            ("07B0", "11", true),
            ("07B0", "20", true),
            ("07B0", "23", true),
            ("0705", "11", false),
            ("0705", "20", false),
            ("0705", "21", true),
            ("0705", "23", true),
            ("0701", "20", false),
            ("0701", "23", true),
            ("0700", "23", true),
            ("0021", "23", false),
            ("0912", "23", false),
        ] {
            let xml = format!(
                r#"<KNX xmlns="http://knx.org/xml/project/{schema}"><ApplicationProgram Id="M-1_A-1" Name="t" MaskVersion="MV-{mask}"><Static><Options Comparable="true" /></Static></ApplicationProgram></KNX>"#
            );
            let app = parse_application_program_str("M-1_A-1", &xml)?;
            assert_eq!(app.schema_number(), schema.parse().ok(), "{mask} {schema}");
            assert_eq!(
                app.downloads_invisible_parameters(),
                writes,
                "{mask} {schema}"
            );
            let background = xml.replace(
                r#"Comparable="true""#,
                r#"DownloadInvisibleParameters="Background""#,
            );
            let app = parse_application_program_str("M-1_A-1", &background)?;
            assert!(!app.downloads_invisible_parameters(), "{mask} {schema}");
        }
        // No namespace: no schema version, so System 7 keeps the template.
        let xml = r#"<KNX><ApplicationProgram Id="M-1_A-1" Name="t" MaskVersion="MV-0705"><Static /></ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        assert_eq!(app.schema_number(), None);
        assert!(!app.downloads_invisible_parameters());
        Ok(())
    }

    /// `SupportsExtendedMemoryServices` decides the memory service above
    /// `0xFFFF` (issue #472); absent means no.
    #[test]
    fn test_parse_application_program_supports_extended_memory_services() -> Result<()> {
        for (options, expected) in [
            (r#"<Options SupportsExtendedMemoryServices="true" />"#, true),
            (
                r#"<Options SupportsExtendedMemoryServices="false" />"#,
                false,
            ),
            (r#"<Options Comparable="true" />"#, false),
        ] {
            let xml = format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t"><Static>{options}</Static></ApplicationProgram></KNX>"#
            );
            let app = parse_application_program_str("M-1_A-1", &xml)?;
            assert_eq!(app.supports_extended_memory_services, expected, "{options}");
        }
        Ok(())
    }

    /// `<Extension EtsDownloadPlugin="">` marks the program (issue #565);
    /// an `<Extension>` without the attribute does not.
    #[test]
    fn test_parse_application_program_ets_download_plugin() -> Result<()> {
        for (extension, expected) in [
            (
                r#"<Extension EtsDownloadPlugin="" EtsUiPlugin="" EtsDataHandler="" />"#,
                true,
            ),
            (r#"<Extension EtsUiPlugin="" />"#, false),
            ("", false),
        ] {
            let xml = format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t"><Static>{extension}<Options /></Static></ApplicationProgram></KNX>"#
            );
            let app = parse_application_program_str("M-1_A-1", &xml)?;
            assert_eq!(app.ets_download_plugin, expected, "{extension}");
        }
        Ok(())
    }

    /// `DynamicTableManagement` comes in both spellings: `1` on the Jung
    /// `A-2088`, `true` on the Theben Meteodata `A-140C` (issue #383).
    #[test]
    fn test_parse_application_program_dynamic_table_management() -> Result<()> {
        for (attr, expected) in [
            (r#" DynamicTableManagement="1""#, true),
            (r#" DynamicTableManagement="true""#, true),
            (r#" DynamicTableManagement="0""#, false),
            (r#" DynamicTableManagement="false""#, false),
            ("", false),
        ] {
            let xml = format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t"{attr}><Static /></ApplicationProgram></KNX>"#
            );
            let app = parse_application_program_str("M-1_A-1", &xml)?;
            assert_eq!(app.dynamic_table_management, expected, "{attr}");
        }
        Ok(())
    }

    /// Issue #537: the Data Secure table capacities, absent when undeclared.
    #[test]
    fn test_parse_application_program_security_capacity() -> Result<()> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t" IsSecureEnabled="true" MaxSecurityGroupKeyTableEntries="1500" MaxSecurityIndividualAddressEntries="5000" MaxSecurityP2PKeyTableEntries="100"><Static /></ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        assert_eq!(
            app.security_capacity,
            SecurityCapacity {
                group_key_table_entries: Some(1500),
                individual_address_entries: Some(5000),
                p2p_key_table_entries: Some(100),
            }
        );
        let plain = r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t"><Static /></ApplicationProgram></KNX>"#;
        assert!(
            parse_application_program_str("M-1_A-1", plain)?
                .security_capacity
                .is_empty()
        );
        Ok(())
    }

    /// Issue #455: `AdditionalAddressesCount` (5 on the Zennio ALLinBOX 1612
    /// `M-0071_A-4A11-13-48E1`), absent when undeclared.
    #[test]
    fn test_parse_application_program_additional_addresses_count() -> Result<()> {
        let xml = |attr: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t"{attr}><Static /></ApplicationProgram></KNX>"#
            )
        };
        let app =
            parse_application_program_str("M-1_A-1", &xml(r#" AdditionalAddressesCount="5""#))?;
        assert_eq!(app.additional_addresses_count, Some(5));
        let app = parse_application_program_str("M-1_A-1", &xml(""))?;
        assert_eq!(app.additional_addresses_count, None);
        Ok(())
    }

    /// Issue #386: `ParameterByteOrder` and the `<ComObjectTable>` placement
    /// (the ABB 6119/20 `A-A002`: little-endian, table at `AS-43FE` + 0).
    #[test]
    fn test_parse_application_program_byte_order_and_object_table() -> Result<()> {
        let xml = |options: &str, table: &str| {
            format!(
                r#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-1_A-1" Name="t"><Static>{table}{options}</Static></ApplicationProgram></KNX>"#
            )
        };
        let app = parse_application_program_str(
            "M-1_A-1",
            &xml(
                r#"<Options ParameterByteOrder="LittleEndian" />"#,
                r#"<ComObjectTable CodeSegment="M-1_A-1_AS-43FE" Offset="2"><ComObject Id="M-1_A-1_O-0" Number="0" /></ComObjectTable>"#,
            ),
        )?;
        assert!(app.parameters_little_endian);
        assert_eq!(
            app.com_object_table,
            Some(TableLocation {
                code_segment: "M-1_A-1_AS-43FE".to_string(),
                offset: 2,
            })
        );
        for options in [r#"<Options ParameterByteOrder="BigEndian" />"#, ""] {
            let app =
                parse_application_program_str("M-1_A-1", &xml(options, "<ComObjectTable />"))?;
            assert!(!app.parameters_little_endian, "{options}");
            assert_eq!(app.com_object_table, None);
        }
        Ok(())
    }

    #[test]
    fn resolves_com_objects_with_dpt_and_flags()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = sample()?;
        let cobs = app.resolved_com_objects();
        assert_eq!(cobs.len(), 2);
        // #0: base C W T + ref R  => CRWT, dpt from ref.
        assert_eq!(cobs[0].number(), 0);
        assert_eq!(cobs[0].dpt(), Some(Dpt::new(1, Some(1))));
        assert_eq!(cobs[0].flags().to_string(), "CRWT");
        // #1: base C only, dpt from ref.
        assert_eq!(cobs[1].number(), 1);
        assert_eq!(cobs[1].dpt(), Some(Dpt::new(9, Some(1))));
        assert_eq!(cobs[1].flags().to_string(), "C");
        assert_eq!(cobs[1].object_size(), Some("2 Bytes"));
        Ok(())
    }

    #[test]
    fn resolve_instance_ref() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = sample()?;
        let (base, cor) = app
            .resolve("O-0_R-1")
            .ok_or("app.resolve(\"O-0_R-1\") missing")?;
        assert_eq!(base.number, 0);
        assert_eq!(cor.dpt, Some(Dpt::new(1, Some(1))));
        assert_eq!(base.flags.merge(cor.flags).to_flags().to_string(), "CRWT");
        Ok(())
    }

    #[test]
    fn parses_all_parameter_type_kinds() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = sample()?;
        let kind = |id: &str| {
            app.parameter_types
                .get(id)
                .map(|t| &t.kind)
                .ok_or(format!("parameter type {id} missing"))
        };
        assert!(matches!(
            kind("M-00FA_A-1_PT-int")?,
            ParameterType::Int {
                min: Some(0),
                max: Some(100),
                size_bits: Some(8),
                signed: false
            }
        ));
        assert!(matches!(
            kind("M-00FA_A-1_PT-sint")?,
            ParameterType::Int { signed: true, .. }
        ));
        match kind("M-00FA_A-1_PT-enum")? {
            ParameterType::Enum { values, .. } => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].value, 0);
                assert_eq!(values[0].text, "Off");
            }
            other => panic!("expected enum, got {other:?}"),
        }
        assert!(matches!(
            kind("M-00FA_A-1_PT-txt")?,
            ParameterType::Text {
                size_bits: Some(112)
            }
        ));
        assert!(matches!(
            kind("M-00FA_A-1_PT-flt")?,
            ParameterType::Float {
                min: Some(_),
                max: Some(_),
                ..
            }
        ));
        assert!(matches!(kind("M-00FA_A-1_PT-none")?, ParameterType::None));
        assert!(matches!(
            kind("M-00FA_A-1_PT-col")?,
            ParameterType::Color {
                space: ColorSpace::Rgb
            }
        ));
        Ok(())
    }

    #[test]
    fn parameter_ref_value_override_applies() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let app = sample()?;
        let rp = app
            .resolved_parameter("M-00FA_A-1_P-1_R-1")
            .ok_or("app.resolved_parameter(\"M-00FA_A-1_P-1_R-1\") missing")?;
        // The parameter's own default is 50; the ref overrides it to 75.
        assert_eq!(rp.value(), Some("75"));
        // P-2's ref overrides Access to None.
        let rp2 = app
            .resolved_parameter("M-00FA_A-1_P-2_R-1")
            .ok_or("app.resolved_parameter(\"M-00FA_A-1_P-2_R-1\") missing")?;
        assert_eq!(rp2.access(), Some("None"));
        Ok(())
    }

    #[test]
    fn parses_memory_location() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = sample()?;
        let mem = app
            .parameters
            .get("M-00FA_A-1_P-1")
            .ok_or("app.parameters.get(\"M-00FA_A-1_P-1\") missing")?
            .memory
            .as_ref()
            .ok_or("app.parameters.get(\"M-00FA_A-1_P-1\").memory.as_ref() missing")?;
        assert_eq!(mem.code_segment.as_deref(), Some("M-00FA_A-1_RS-4"));
        assert_eq!(mem.offset, Some(3));
        assert_eq!(mem.bit_offset, Some(2));
        // A parameter with no <Memory> child has None.
        assert!(
            app.parameters
                .get("M-00FA_A-1_P-2")
                .ok_or("app.parameters.get(\"M-00FA_A-1_P-2\") missing")?
                .memory
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn parses_code_segments_with_inline_data() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let app = sample()?;
        assert_eq!(app.code_segments.len(), 2);
        let rel = app
            .code_segments
            .get("M-00FA_A-1_RS-4")
            .ok_or("app.code_segments.get(\"M-00FA_A-1_RS-4\") missing")?;
        assert_eq!(rel.kind, SegmentKind::Relative);
        assert_eq!(rel.size, Some(10));
        assert_eq!(rel.load_state_machine, Some(4));
        assert_eq!(rel.address_or_offset, Some(0));
        // The `<Data>` base64 decodes to the segment's image bytes and the
        // `<Mask>` to its parallel ownership mask.
        assert_eq!(rel.data.as_deref(), Some([0u8; 10].as_slice()));
        assert_eq!(rel.mask.as_deref(), Some([0xFFu8; 12].as_slice()));
        // The self-closing absolute segment stays metadata-only.
        let abs = app
            .code_segments
            .get("M-00FA_A-1_AS-1")
            .ok_or("app.code_segments.get(\"M-00FA_A-1_AS-1\") missing")?;
        assert_eq!(abs.kind, SegmentKind::Absolute);
        assert_eq!(abs.address_or_offset, Some(16384));
        assert!(abs.data.is_none());
        assert!(abs.mask.is_none());
        Ok(())
    }

    #[test]
    fn parses_every_load_op_variant() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = sample()?;
        assert_eq!(app.load_procedures.len(), 1);
        assert_eq!(app.load_procedures[0].merge_id.as_deref(), Some("1"));
        let ops = &app.load_procedures[0].ops;
        assert!(matches!(ops[0], LoadOp::Connect));
        assert!(matches!(ops[1], LoadOp::Unload { lsm_idx: Some(1) }));
        assert!(matches!(ops[2], LoadOp::Load { lsm_idx: Some(2) }));
        assert!(matches!(
            ops[3],
            LoadOp::TaskSegment {
                lsm_idx: Some(1),
                address: Some(16384)
            }
        ));
        assert!(matches!(ops[4], LoadOp::TaskCtrl1 { count: Some(1), .. }));
        assert!(matches!(
            ops[5],
            LoadOp::RelSegment {
                size: Some(19155),
                ..
            }
        ));
        assert!(matches!(
            ops[6],
            LoadOp::AbsSegment {
                size: Some(511),
                ..
            }
        ));
        assert!(matches!(
            ops[7],
            LoadOp::WriteRelMem {
                obj_idx: Some(5),
                size: Some(10),
                ..
            }
        ));
        assert!(matches!(
            ops[8],
            LoadOp::WriteProp {
                obj_type: Some(11),
                prop_id: Some(204),
                ..
            }
        ));
        assert!(matches!(ops[9], LoadOp::LoadCompleted { lsm_idx: Some(1) }));
        assert!(matches!(ops[10], LoadOp::Restart));
        assert!(matches!(ops[11], LoadOp::Disconnect));
        // LdCtrlLoadImageProp is a typed op carrying its target object + PropId.
        assert!(matches!(
            ops[12],
            LoadOp::LoadImageProp {
                obj_idx: Some(5),
                prop_id: Some(27),
                count: None,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn parses_load_image_prop_variants() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Both the ObjIdx form (MDT A-0007, Jung 23024) and the ObjType +
        // Occurrence system-object form, plus a Count attribute.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="x">
          <LoadProcedures><LoadProcedure MergeId="7">
           <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />
           <LdCtrlLoadImageProp ObjIdx="4" PropId="27" Count="2" />
           <LdCtrlLoadImageProp ObjType="6" Occurrence="1" PropId="27" />
          </LoadProcedure></LoadProcedures>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        let ops = &app.load_procedures[0].ops;
        assert!(matches!(
            ops[0],
            LoadOp::LoadImageProp {
                obj_idx: Some(1),
                prop_id: Some(27),
                count: None,
                ..
            }
        ));
        assert!(matches!(
            ops[1],
            LoadOp::LoadImageProp {
                obj_idx: Some(4),
                count: Some(2),
                ..
            }
        ));
        assert!(matches!(
            ops[2],
            LoadOp::LoadImageProp {
                obj_idx: None,
                obj_type: Some(6),
                occurrence: Some(1),
                prop_id: Some(27),
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn parses_master_reset() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The KNX Virtual shape: an LdCtrlMasterReset carrying EraseCode and
        // ChannelNumber, mid-procedure between a RelSegment and a WriteRelMem.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="x">
          <LoadProcedures><LoadProcedure MergeId="1">
           <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
           <LdCtrlMasterReset EraseCode="4" ChannelNumber="0" />
           <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
          </LoadProcedure></LoadProcedures>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        let ops = &app.load_procedures[0].ops;
        assert!(matches!(ops[0], LoadOp::RelSegment { .. }));
        assert!(matches!(
            ops[1],
            LoadOp::MasterReset {
                erase_code: Some(4),
                channel_number: Some(0),
            }
        ));
        assert!(matches!(ops[2], LoadOp::WriteRelMem { .. }));
        Ok(())
    }

    #[test]
    fn test_push_load_op_rel_segment_fill_flag()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The Jung LED A-3030 shape: the code segment (obj4) sets Fill="1" so the
        // device pre-fills the allocation (obj4 alloc `030b000028c1 01 00 0000`),
        // while the table objects keep Fill="0". A procedure with no `Fill`
        // attribute (the DA.tp shape) parses to `SegmentFill::NONE` so the no-fill
        // allocation is byte-identical.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="x">
          <LoadProcedures><LoadProcedure MergeId="1">
           <LdCtrlRelSegment LsmIdx="4" Size="10433" AppliesTo="full" Fill="1" />
           <LdCtrlRelSegment LsmIdx="3" Size="2" AppliesTo="full" Fill="0" />
           <LdCtrlRelSegment LsmIdx="2" Size="2" AppliesTo="full" />
           <LdCtrlRelSegment LsmIdx="1" Size="2" AppliesTo="full" Fill="1" FillByte="0xAB" />
          </LoadProcedure></LoadProcedures>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        let ops = &app.load_procedures[0].ops;
        // Fill="1" with no FillByte → Some(0) (the Jung LED A-3030 code segment).
        assert!(matches!(
            ops[0],
            LoadOp::RelSegment {
                fill: SegmentFill { mode: 1, fill: 0 },
                lsm_idx: Some(4),
                ..
            }
        ));
        // Fill="0" → mode 0 (no pre-fill).
        assert!(matches!(
            ops[1],
            LoadOp::RelSegment {
                fill: SegmentFill::NONE,
                ..
            }
        ));
        // Fill absent → NONE (the DA.tp default).
        assert!(matches!(
            ops[2],
            LoadOp::RelSegment {
                fill: SegmentFill::NONE,
                ..
            }
        ));
        // Fill="1" with an explicit hex FillByte.
        assert!(matches!(
            ops[3],
            LoadOp::RelSegment {
                fill: SegmentFill {
                    mode: 1,
                    fill: 0xAB
                },
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn test_push_load_op_rel_segment_mode_is_the_fill_flag() -> Result<()> {
        // The schema spelling (issue #123): `Mode` is the fill flag and `Fill`
        // the fill byte. The Jung F50 app allocates obj4 with `Mode="1"
        // Fill="0"` and ETS sends the fill flag set with byte 00; its `par`
        // twin `Mode="0" Fill="0"` does not fill.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/21">
         <ApplicationProgram Id="M-1_A-1" Name="x">
          <LoadProcedures><LoadProcedure MergeId="2">
           <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6152" Mode="1" Fill="0" />
           <LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="6152" Mode="0" Fill="0" />
           <LdCtrlRelSegment LsmIdx="4" Size="2" Mode="1" Fill="255" />
           <LdCtrlRelSegment LsmIdx="4" Size="256" Mode="0" Fill="255" />
          </LoadProcedure></LoadProcedures>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        let ops = &app.load_procedures[0].ops;
        let fills: Vec<SegmentFill> = ops
            .iter()
            .filter_map(|op| match op {
                LoadOp::RelSegment { fill, .. } => Some(*fill),
                _ => None,
            })
            .collect();
        assert_eq!(
            fills,
            vec![
                SegmentFill::filled(0),
                SegmentFill::NONE,
                SegmentFill::filled(0xFF),
                SegmentFill {
                    mode: 0,
                    fill: 0xFF
                },
            ]
        );
        assert_eq!(fills[0].prefill(), Some(0));
        assert_eq!(fills[1].prefill(), None);
        // Mode 0 with a Fill octet: no pre-fill, but the octet is kept for
        // the record (ETS sends `00 ff` for `syn-relseg-fill`, issue #480).
        assert_eq!(fills[3].prefill(), None);
        Ok(())
    }

    #[test]
    fn test_parse_dynamic_tree_keeps_modules_and_nested_chooses() -> Result<()> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/21">
         <ApplicationProgram Id="A" Name="x">
          <ModuleDefs><ModuleDef Id="A_MD-1">
           <Dynamic><ParameterBlock Id="A_MD-1_PB-1"><ComObjectRefRef RefId="A_MD-1_O-1_R-1" /></ParameterBlock></Dynamic>
          </ModuleDef></ModuleDefs>
          <Dynamic>
           <Channel Id="A_CH-1"><ParameterBlock Id="A_PB-1">
            <ParameterRefRef RefId="A_P-1_R-1" />
            <choose ParamRefId="A_P-1_R-1">
             <when test="0" />
             <when test="1">
              <choose ParamRefId="A_P-2_R-2"><when default="true">
               <Module Id="A_MD-1_M-3" RefId="A_MD-1"><NumericArg RefId="A_MD-1_A-1" Value="65" /></Module>
              </when></choose>
             </when>
            </choose>
            <Assign TargetParamRefRef="A_P-3_R-3" SourceParamRefRef="A_P-1_R-1" />
           </ParameterBlock></Channel>
          </Dynamic>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("A", xml)?;
        // The containers are kept now; this test pins the flattened view.
        assert_eq!(
            app.module_dynamics
                .get("MD-1")
                .map(|b| flatten_containers(b)),
            Some(vec![DynamicNode::ComObjectRefRef("MD-1_O-1_R-1".into())])
        );
        let dynamic = flatten_containers(&app.dynamic);
        assert_eq!(dynamic.len(), 3);
        assert_eq!(dynamic[0], DynamicNode::ParameterRefRef("P-1_R-1".into()));
        let DynamicNode::Choose {
            param_ref_id,
            whens,
        } = &dynamic[1]
        else {
            panic!("expected a choose, got {:?}", dynamic[1]);
        };
        assert_eq!(param_ref_id, "P-1_R-1");
        assert_eq!(whens.len(), 2);
        assert!(whens[0].children.is_empty());
        let DynamicNode::Choose { whens: inner, .. } = &whens[1].children[0] else {
            panic!("expected a nested choose");
        };
        assert_eq!(inner[0].test, WhenTest::Default);
        let DynamicNode::Module {
            id,
            module_def,
            args,
            ..
        } = &inner[0].children[0]
        else {
            panic!("expected a module");
        };
        assert_eq!((id.as_str(), module_def.as_str()), ("MD-1_M-3", "MD-1"));
        assert_eq!(args.get("MD-1_A-1"), Some(&65));
        assert!(
            matches!(&dynamic[2], DynamicNode::Assign { target, source: Some(src), .. }
            if target == "P-3_R-3" && src == "P-1_R-1")
        );
        assert_eq!(app.module_instances[0].id, "MD-1_M-3");
        Ok(())
    }

    #[test]
    fn parses_compare_prop_variants() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // The MDT SCN-DA64x DALI-gateway shape: InlineData (hex) + optional Mask,
        // addressed by ObjIdx, with OnError children; a self-closing form; an
        // ObjType-addressed form; and a Range-only form (no InlineData).
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="x">
          <LoadProcedures><LoadProcedure MergeId="7">
           <LdCtrlCompareProp InlineData="00000001620100000000" ObjIdx="0" PropId="78">
            <OnError Cause="CompareMismatch" MessageRef="M-1_A-1_M-1" />
           </LdCtrlCompareProp>
           <LdCtrlCompareProp InlineData="00010000" Mask="00FF0000" ObjIdx="0" PropId="19" />
           <LdCtrlCompareProp InlineData="0004" ObjType="0" PropId="12" />
           <LdCtrlCompareProp Range="[2216203124736,]" ObjIdx="0" PropId="201" />
          </LoadProcedure></LoadProcedures>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        let ops = &app.load_procedures[0].ops;
        // Element with children (OnError) parses to a typed CompareProp, not Raw.
        match &ops[0] {
            LoadOp::CompareProp {
                obj_idx,
                prop_id,
                inline_data,
                mask,
                range,
                ..
            } => {
                assert_eq!(*obj_idx, Some(0));
                assert_eq!(*prop_id, Some(78));
                assert_eq!(
                    inline_data.as_deref(),
                    Some([0x00, 0x00, 0x00, 0x01, 0x62, 0x01, 0x00, 0x00, 0x00, 0x00].as_slice())
                );
                assert!(mask.is_none());
                assert!(range.is_none());
            }
            other => panic!("expected CompareProp, got {other:?}"),
        }
        // Self-closing with a Mask.
        assert!(matches!(
            &ops[1],
            LoadOp::CompareProp {
                inline_data: Some(d),
                mask: Some(m),
                prop_id: Some(19),
                ..
            } if d == &[0x00, 0x01, 0x00, 0x00] && m == &[0x00, 0xFF, 0x00, 0x00]
        ));
        // ObjType-addressed form.
        assert!(matches!(
            &ops[2],
            LoadOp::CompareProp {
                obj_idx: None,
                obj_type: Some(0),
                prop_id: Some(12),
                ..
            }
        ));
        // Range-only form: no InlineData bytes.
        assert!(matches!(
            &ops[3],
            LoadOp::CompareProp {
                inline_data: None,
                range: Some(r),
                prop_id: Some(201),
                ..
            } if r == "[2216203124736,]"
        ));
        Ok(())
    }

    #[test]
    fn en_us_translation_overrides_text() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="Deutsch">
          <Static><ComObjectTable>
           <ComObject Id="M-1_A-1_O-0" Number="0" Text="Schalten" CommunicationFlag="Enabled" />
          </ComObjectTable></Static>
          <Languages><Language Identifier="en-US">
           <TranslationUnit RefId="M-1_A-1">
            <TranslationElement RefId="M-1_A-1"><Translation AttributeName="Name" Text="English" /></TranslationElement>
            <TranslationElement RefId="M-1_A-1_O-0"><Translation AttributeName="Text" Text="Switch" /></TranslationElement>
           </TranslationUnit>
          </Language>
          <Language Identifier="fr-FR">
           <TranslationUnit RefId="M-1_A-1">
            <TranslationElement RefId="M-1_A-1"><Translation AttributeName="Name" Text="Francais" /></TranslationElement>
           </TranslationUnit>
          </Language></Languages>
         </ApplicationProgram>
        </KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        assert_eq!(app.name.as_deref(), Some("English"));
        assert_eq!(
            app.com_objects
                .get("M-1_A-1_O-0")
                .ok_or("app.com_objects.get(\"M-1_A-1_O-0\") missing")?
                .text
                .as_deref(),
            Some("Switch")
        );
        Ok(())
    }

    const LANGUAGE_SAMPLE: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="Actuator" DefaultLanguage="en-US">
          <Static>
           <ParameterTypes>
            <ParameterType Id="M-1_A-1_PT-1" Name="mode"><TypeRestriction Base="Value" SizeInBit="8">
             <Enumeration Text="Blind" Value="0" Id="M-1_A-1_PT-1_EN-0" />
             <Enumeration Text="Shutter" Value="1" Id="M-1_A-1_PT-1_EN-1" />
            </TypeRestriction></ParameterType>
           </ParameterTypes>
           <ComObjectTable>
            <ComObject Id="M-1_A-1_O-0" Number="0" Text="Blind" FunctionText="Long-time operation" />
           </ComObjectTable>
          </Static>
          <Languages><Language Identifier="de-DE">
           <TranslationUnit RefId="M-1_A-1">
            <TranslationElement RefId="M-1_A-1_PT-1_EN-1"><Translation AttributeName="Text" Text="Rollladen" /></TranslationElement>
            <TranslationElement RefId="M-1_A-1_O-0">
             <Translation AttributeName="Text" Text="Jalousie" />
             <Translation AttributeName="FunctionText" Text="Langzeitbetrieb" />
            </TranslationElement>
           </TranslationUnit>
          </Language></Languages>
         </ApplicationProgram>
        </KNX>"#;

    #[test]
    fn test_parse_application_program_in_applies_the_chosen_language() -> Result<()> {
        let app = parse_application_program_in("M-1_A-1", LANGUAGE_SAMPLE.as_bytes(), "de-de")?;
        let object = app.com_objects.get("M-1_A-1_O-0");
        assert_eq!(object.and_then(|o| o.text.as_deref()), Some("Jalousie"));
        assert_eq!(
            object.and_then(|o| o.function_text.as_deref()),
            Some("Langzeitbetrieb")
        );
        let texts: Vec<&str> = match app.parameter_types.get("M-1_A-1_PT-1").map(|d| &d.kind) {
            Some(ParameterType::Enum { values, .. }) => {
                values.iter().map(|v| v.text.as_str()).collect()
            }
            _ => Vec::new(),
        };
        // An enumeration the layer does not translate keeps its default text.
        assert_eq!(texts, ["Blind", "Rollladen"]);
        assert_eq!(app.default_language.as_deref(), Some("en-US"));

        // The en-US parse keeps the untranslated texts.
        let app = parse_application_program("M-1_A-1", LANGUAGE_SAMPLE.as_bytes())?;
        let object = app.com_objects.get("M-1_A-1_O-0");
        assert_eq!(
            object.and_then(|o| o.function_text.as_deref()),
            Some("Long-time operation")
        );
        Ok(())
    }

    #[test]
    fn test_parse_application_program_in_keeps_enum_labels_of_every_language() -> Result<()> {
        // Issue #231: the image builder matches a label against the parse
        // language, the default text and every layer, so each is kept.
        for language in ["de-DE", "en-US"] {
            let app =
                parse_application_program_in("M-1_A-1", LANGUAGE_SAMPLE.as_bytes(), language)?;
            let values = match app.parameter_types.get("M-1_A-1_PT-1").map(|d| &d.kind) {
                Some(ParameterType::Enum { values, .. }) => values.clone(),
                _ => Vec::new(),
            };
            assert_eq!(values.len(), 2, "parsed in {language}");
            let shutter = values.iter().find(|v| v.value == 1);
            assert_eq!(shutter.map(|v| v.default_text.as_str()), Some("Shutter"));
            assert_eq!(
                shutter
                    .and_then(|v| v.translations.get("de-DE"))
                    .map(String::as_str),
                Some("Rollladen"),
                "parsed in {language}"
            );
            let blind = values.iter().find(|v| v.value == 0);
            assert!(blind.is_some_and(|v| v.translations.is_empty()));
        }
        Ok(())
    }

    #[test]
    fn test_program_languages_scans_default_and_layers() {
        let langs = program_languages(LANGUAGE_SAMPLE.as_bytes());
        assert_eq!(langs.default.as_deref(), Some("en-US"));
        assert_eq!(
            langs
                .translations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["de-DE"]
        );
        assert!(langs.offers("de-DE") && langs.offers("EN-us"));
        assert!(!langs.offers("fr-FR"));
        assert_eq!(program_languages(b"<KNX/>"), ProgramLanguages::default());
    }

    const MODULE_SAMPLE: &str = r#"<?xml version="1.0"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ApplicationProgram Id="M-0004_A-1" MaskVersion="MV-07B0" Name="Jung">
    <Dynamic>
      <Channel Id="M-0004_A-1_MD-1_CH-13" Name="Relaisausgänge"
        Text="{{ArgBeschriftungRelais}} {{ArgBeschriftung}} ({{0:...}})" Number="13" />
      <ParameterBlock>
        <Module Id="M-0004_A-1_MD-1">
          <Arguments>
            <Argument Id="M-0004_A-1_MD-1_A-3" Name="ArgBeschriftung" Type="Text" />
            <Argument Id="M-0004_A-1_MD-1_A-5" Name="ArgBeschriftungRelais" Type="Text" />
          </Arguments>
        </Module>
      </ParameterBlock>
    </Dynamic>
  </ApplicationProgram>
</KNX>"#;

    #[test]
    fn parses_module_parameter_base_offset() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // A module parameter's <Memory> carries a BaseOffset naming the argument
        // whose per-instance value is added to the declared offset; a plain
        // parameter has none.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0004_A-1" MaskVersion="MV-07B0" Name="Jung"><Static>
          <Parameters>
           <Parameter Id="M-0004_A-1_MD-1_P-3" Name="_VA_Label" ParameterType="M-0004_A-1_PT-0" Value="1">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="1" BitOffset="0" BaseOffset="M-0004_A-1_MD-1_A-1" />
           </Parameter>
           <Parameter Id="M-0004_A-1_P-9" Name="plain" ParameterType="M-0004_A-1_PT-0" Value="0">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="5" BitOffset="0" />
           </Parameter>
          </Parameters>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-0004_A-1", xml)?;
        let m = app
            .parameters
            .get("M-0004_A-1_MD-1_P-3")
            .ok_or("app.parameters.get(\"M-0004_A-1_MD-1_P-3\") missing")?
            .memory
            .as_ref()
            .ok_or("app.parameters.get(\"M-0004_A-1_MD-1_P-3\").memory.as_ref() missing")?;
        assert_eq!(m.offset, Some(1));
        assert_eq!(m.base_offset.as_deref(), Some("M-0004_A-1_MD-1_A-1"));
        // The plain parameter has no BaseOffset.
        assert!(
            app.parameters
                .get("M-0004_A-1_P-9")
                .ok_or("app.parameters.get(\"M-0004_A-1_P-9\") missing")?
                .memory
                .as_ref()
                .ok_or("app.parameters.get(\"M-0004_A-1_P-9\").memory.as_ref() missing")?
                .base_offset
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn parses_union_block_members_and_default()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A `<Union>` (shape taken from the Zennio FIX2 dimmer): one base
        // `<Memory>` then member `<Parameter>`s carrying union-relative
        // Offset/BitOffset. The `DefaultUnionParameter="1"` member is the default.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" MaskVersion="MV-07B0" Name="x"><Static>
          <Union SizeInBit="8">
           <Memory CodeSegment="M-1_A-1_RS-1" Offset="56" BitOffset="0" />
           <Parameter Id="M-1_A-1_UP-1" Name="a" DefaultUnionParameter="1" ParameterType="M-1_A-1_PT-0" Value="75" Offset="0" BitOffset="0" />
           <Parameter Id="M-1_A-1_UP-2" Name="b" DefaultUnionParameter="0" ParameterType="M-1_A-1_PT-0" Value="1" Offset="0" BitOffset="0" />
           <Parameter Id="M-1_A-1_UP-3" Name="c" ParameterType="M-1_A-1_PT-0" Value="9" Offset="1" BitOffset="1" />
          </Union>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        assert_eq!(app.unions.len(), 1);
        let u = &app.unions[0];
        assert_eq!(u.size_bits, Some(8));
        let mem = u.memory.as_ref().ok_or("union base memory")?;
        assert_eq!(mem.code_segment.as_deref(), Some("M-1_A-1_RS-1"));
        assert_eq!(mem.offset, Some(56));
        // Three members captured with their union-relative positions.
        assert_eq!(u.members.len(), 3);
        assert_eq!(u.members[0].parameter, "M-1_A-1_UP-1");
        assert!(u.members[0].is_default);
        assert_eq!(u.members[0].offset, Some(0));
        assert!(!u.members[1].is_default);
        assert_eq!(u.members[2].offset, Some(1));
        assert_eq!(u.members[2].bit_offset, Some(1));
        // The member parameters are also present in the normal parameter map
        // (so their type/default resolve during image computation).
        assert_eq!(
            app.parameters
                .get("M-1_A-1_UP-1")
                .ok_or("app.parameters.get(\"M-1_A-1_UP-1\") missing")?
                .default
                .as_deref(),
            Some("75")
        );
        Ok(())
    }

    #[test]
    fn parses_union_default_true_spelling() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // ETS files spell the default flag as `"1"` or `"true"`; both must count.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" MaskVersion="MV-07B0" Name="x"><Static>
          <Union SizeInBit="8">
           <Memory CodeSegment="M-1_A-1_RS-1" Offset="10" BitOffset="0" />
           <Parameter Id="M-1_A-1_UP-1" Name="a" ParameterType="M-1_A-1_PT-0" Value="0" Offset="0" BitOffset="0" />
           <Parameter Id="M-1_A-1_UP-2" Name="b" DefaultUnionParameter="true" ParameterType="M-1_A-1_PT-0" Value="7" Offset="0" BitOffset="0" />
          </Union>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        let u = &app.unions[0];
        assert!(!u.members[0].is_default);
        assert!(u.members[1].is_default, "\"true\" counts as default");
        Ok(())
    }

    #[test]
    fn parses_channels_and_arguments() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("M-0004_A-1", MODULE_SAMPLE)?;
        let ch = app.channel("MD-1_CH-13").ok_or("channel def")?;
        assert_eq!(ch.name.as_deref(), Some("Relaisausgänge"));
        assert_eq!(
            ch.text.as_deref(),
            Some("{{ArgBeschriftungRelais}} {{ArgBeschriftung}} ({{0:...}})")
        );
        assert_eq!(app.argument_id("ArgBeschriftung"), Some("MD-1_A-3"));
        assert_eq!(app.argument_id("ArgBeschriftungRelais"), Some("MD-1_A-5"));
        Ok(())
    }

    /// A Dynamic section shaped like real product data: a channel parameter
    /// block with an unconditional com-object, a `<choose>` whose branches use
    /// every `test` spelling ETS emits (single value, space-separated list,
    /// negative, comparison, `default`), and a **nested** `<choose>` inside one
    /// of those branches.
    const NESTED_CHOOSE_SAMPLE: &str = r#"<?xml version="1.0"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ApplicationProgram Id="M-1_A-1" MaskVersion="MV-07B0" Name="x">
    <Dynamic>
      <ParameterBlock>
        <ComObjectRefRef RefId="M-1_A-1_MD-1_O-0_R-0" />
        <choose ParamRefId="M-1_A-1_MD-1_P-1_R-1">
          <when test="1">
            <ComObjectRefRef RefId="M-1_A-1_MD-1_O-1_R-1" />
            <choose ParamRefId="M-1_A-1_MD-1_P-2_R-2">
              <when test="7">
                <ComObjectRefRef RefId="M-1_A-1_MD-1_O-7_R-7" />
              </when>
              <when default="true">
                <ComObjectRefRef RefId="M-1_A-1_MD-1_O-8_R-8" />
              </when>
            </choose>
            <ComObjectRefRef RefId="M-1_A-1_MD-1_O-9_R-9" />
          </when>
          <when test="0 2">
            <ComObjectRefRef RefId="M-1_A-1_MD-1_O-2_R-2" />
          </when>
          <when test="-1">
            <ComObjectRefRef RefId="M-1_A-1_MD-1_O-3_R-3" />
          </when>
          <when test="!=0">
            <ComObjectRefRef RefId="M-1_A-1_MD-1_O-4_R-4" />
          </when>
          <when default="true">
            <ComObjectRefRef RefId="M-1_A-1_MD-1_O-5_R-5" />
          </when>
        </choose>
      </ParameterBlock>
    </Dynamic>
  </ApplicationProgram>
</KNX>"#;

    /// Regression: `<choose>`/`<when>` were tracked in single slots, so a nested
    /// `<choose>` (ubiquitous in real Dynamic sections) overwrote the enclosing
    /// one — the inner `</when>` took the outer branch's collected refs and the
    /// outer `</choose>` found nothing to attach. Each frame now keeps its own
    /// refs.
    #[test]
    fn test_parse_application_program_nested_choose_keeps_frames_apart()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("M-1_A-1", NESTED_CHOOSE_SAMPLE)?;
        let mem = app
            .channel_membership
            .as_ref()
            .ok_or("channel membership")?;

        // Only the ref written directly under the block is unconditional; no
        // branch member leaks up.
        assert_eq!(mem.unconditional, vec!["MD-1_O-0_R-0".to_string()]);

        // Two groups: the inner one closes first, then the outer.
        assert_eq!(mem.conditional.len(), 2);
        let inner = &mem.conditional[0];
        let outer = &mem.conditional[1];
        assert_eq!(inner.param_ref_id, "MD-1_P-2_R-2");
        assert_eq!(outer.param_ref_id, "MD-1_P-1_R-1");

        // The inner group keeps its own members...
        assert_eq!(inner.members_for(7), ["MD-1_O-7_R-7".to_string()]);
        // ...and its `<when default>` covers every other value.
        assert_eq!(inner.members_for(3), ["MD-1_O-8_R-8".to_string()]);

        // ...while the outer branch keeps the refs written around the nested
        // `<choose>`, and nothing of the inner one.
        let outer_branch_1 = outer
            .branches_all
            .iter()
            .find(|b| b.test == WhenTest::Values(vec![1]))
            .ok_or("the test=\"1\" branch")?;
        assert_eq!(
            outer_branch_1.members,
            vec!["MD-1_O-1_R-1".to_string(), "MD-1_O-9_R-9".to_string()]
        );
        Ok(())
    }

    /// Every `test` spelling ETS writes: a single value, a space-separated list,
    /// a negative value, a comparison and `default`. A list used to fail
    /// `parse::<i64>()` and route its members to `unconditional` — "present on
    /// every channel" — which is the opposite of conditional.
    #[test]
    fn test_parse_application_program_when_test_spellings()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("M-1_A-1", NESTED_CHOOSE_SAMPLE)?;
        let mem = app
            .channel_membership
            .as_ref()
            .ok_or("channel membership")?;
        let outer = &mem.conditional[1];

        // The flattened exact-value view: `test="0 2"` contributes both values.
        let exact: Vec<i64> = outer.branches.iter().map(|(v, _)| *v).collect();
        assert_eq!(exact, vec![1, 0, 2, -1]);

        // Selection honours every spelling.
        assert_eq!(
            outer.members_for(1),
            ["MD-1_O-1_R-1".to_string(), "MD-1_O-9_R-9".to_string()]
        );
        assert_eq!(outer.members_for(2), ["MD-1_O-2_R-2".to_string()]);
        assert_eq!(outer.members_for(-1), ["MD-1_O-3_R-3".to_string()]);
        // 0 matches the `test="0 2"` branch before the `!=0` one.
        assert_eq!(outer.members_for(0), ["MD-1_O-2_R-2".to_string()]);
        // 5 matches nothing exact, so the first comparison branch that matches
        // wins (`!=0`).
        assert_eq!(outer.members_for(5), ["MD-1_O-4_R-4".to_string()]);
        // And the `<when default>` is the fallback when nothing matched at all.
        let fallback = ConditionalGroup {
            param_ref_id: "p".to_string(),
            branches: Vec::new(),
            branches_all: vec![
                WhenBranch {
                    test: WhenTest::Values(vec![1]),
                    members: vec!["a".to_string()],
                },
                WhenBranch {
                    test: WhenTest::Default,
                    members: vec!["b".to_string()],
                },
            ],
        };
        assert_eq!(fallback.members_for(9), ["b".to_string()]);
        Ok(())
    }

    #[test]
    fn test_when_test_parse_grammar() {
        assert_eq!(WhenTest::parse(Some("1"), None), WhenTest::Values(vec![1]));
        assert_eq!(
            WhenTest::parse(Some(" 0 2 "), None),
            WhenTest::Values(vec![0, 2])
        );
        assert_eq!(
            WhenTest::parse(Some("-1"), None),
            WhenTest::Values(vec![-1])
        );
        assert_eq!(
            WhenTest::parse(Some("!=0"), None),
            WhenTest::Compare {
                op: CompareOp::Ne,
                value: 0
            }
        );
        assert_eq!(
            WhenTest::parse(Some(">=2"), None),
            WhenTest::Compare {
                op: CompareOp::Ge,
                value: 2
            }
        );
        assert_eq!(
            WhenTest::parse(Some("<3"), None),
            WhenTest::Compare {
                op: CompareOp::Lt,
                value: 3
            }
        );
        // `default="true"` wins over a test; `default="false"` does not.
        assert_eq!(WhenTest::parse(Some("1"), Some("true")), WhenTest::Default);
        assert_eq!(
            WhenTest::parse(Some("1"), Some("false")),
            WhenTest::Values(vec![1])
        );
        // Anything else is preserved, and matches nothing.
        let unknown = WhenTest::parse(Some("$Arg > 2"), None);
        assert_eq!(unknown, WhenTest::Unknown("$Arg > 2".to_string()));
        assert!(!unknown.matches(3));
    }

    #[test]
    fn parses_base_number_ref() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <ApplicationProgram Id="M-1_A-1" Name="x">
            <Static><ComObjectTable>
              <ComObject Id="M-1_A-1_MD-1_O-2" Number="2" BaseNumber="M-1_A-1_MD-1_A-9" Text="Rel" CommunicationFlag="Enabled" />
            </ComObjectTable></Static>
          </ApplicationProgram>
        </KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        assert_eq!(
            app.com_objects
                .get("M-1_A-1_MD-1_O-2")
                .ok_or("app.com_objects.get(\"M-1_A-1_MD-1_O-2\") missing")?
                .base_number_ref
                .as_deref(),
            Some("M-1_A-1_MD-1_A-9")
        );
        Ok(())
    }

    #[test]
    fn invalid_segment_base64_reports_segment_decode()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A corrupt `<Data>` payload must surface as the dedicated
        // SegmentDecode variant, naming the segment and the `Data` field, not
        // the vague stringly Malformed catch-all.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <ApplicationProgram Id="M-1_A-1" Name="x">
            <Static><LoadProcedures>
              <RelativeSegment Id="M-1_A-1_RS-4-1-0" Size="4" LoadStateMachine="4" Offset="0">
                <Data>@@not base64@@</Data>
              </RelativeSegment>
            </LoadProcedures></Static>
          </ApplicationProgram>
        </KNX>"#;
        let err = parse_application_program_str("M-1_A-1", xml)
            .err()
            .ok_or("corrupt base64 must fail")?;
        match err {
            EtsError::SegmentDecode { segment, field, .. } => {
                assert_eq!(segment, "M-1_A-1_RS-4-1-0");
                assert_eq!(field, "Data");
            }
            other => panic!("expected SegmentDecode, got {other:?}"),
        }
        // The rendered message is actionable: it names the segment and field.
        let rendered = parse_application_program_str("M-1_A-1", xml)
            .err()
            .ok_or("corrupt base64 must fail")?
            .to_string();
        assert!(
            rendered.contains("M-1_A-1_RS-4-1-0") && rendered.contains("Data"),
            "message should name segment and field: {rendered}"
        );
        Ok(())
    }

    #[test]
    fn test_parse_property_located_parameters_and_guarded_load_ops()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/20">
         <ApplicationProgram Id="M-4_A-1" MaskVersion="MV-0021" Name="IP">
          <Static>
           <Parameters>
            <Parameter Id="M-4_A-1_P-100" Name="ip1" Value="192.168.255.255">
             <Property ObjectType="11" PropertyId="205" Offset="4" BitOffset="0" />
            </Parameter>
            <Parameter Id="M-4_A-1_P-36" Name="label" Value="x">
             <Property ObjectIndex="6" Occurrence="1" PropertyId="60" Offset="0" BitOffset="2" />
            </Parameter>
            <Parameter Id="M-4_A-1_P-18" Name="mode" Value="1" />
           </Parameters>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlCompareProp InlineData="0004" ObjType="0" PropId="12" />
             <choose ParamRefId="M-4_A-1_P-18_R-8">
              <when test="&gt;=3">
               <LdCtrlWriteProp ObjIdx="6" PropId="60" Verify="false" />
              </when>
              <when default="true">
               <LdCtrlCompareProp InlineData="01" ObjIdx="0" PropId="19" />
              </when>
             </choose>
             <LdCtrlWriteProp ObjType="11" PropId="205" Count="8" Verify="true" Occurrence="0" />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-4_A-1", xml)?;
        let ip = app
            .parameters
            .get("M-4_A-1_P-100")
            .and_then(|p| p.property.clone())
            .ok_or("P-100 has a property location")?;
        assert_eq!(
            ip,
            PropertyLocation {
                object_index: None,
                object_type: Some(11),
                occurrence: None,
                property_id: 205,
                offset: 4,
                bit_offset: 0,
            }
        );
        let label = app
            .parameters
            .get("M-4_A-1_P-36")
            .and_then(|p| p.property.clone())
            .ok_or("P-36 has a property location")?;
        assert_eq!(label.object_index, Some(6));
        assert_eq!(label.occurrence, Some(1));
        assert_eq!(label.bit_offset, 2);
        assert!(
            app.parameters
                .get("M-4_A-1_P-18")
                .is_some_and(|p| p.property.is_none())
        );

        let lp = &app.load_procedures[0];
        assert_eq!(lp.ops.len(), 4);
        assert_eq!(
            lp.chooses,
            vec![LoadChoose {
                param_ref_id: "P-18_R-8".to_string(),
                tests: vec![WhenTest::parse(Some(">=3"), None), WhenTest::Default,],
            }]
        );
        assert!(lp.guards_of(0).is_empty());
        assert_eq!(
            lp.guards_of(1),
            &[LoadGuard {
                choose: 0,
                branch: 0
            }]
        );
        assert_eq!(
            lp.guards_of(2),
            &[LoadGuard {
                choose: 0,
                branch: 1
            }]
        );
        assert!(lp.guards_of(3).is_empty());
        assert!(matches!(
            &lp.ops[3],
            LoadOp::WriteProp {
                count: Some(8),
                verify: Some(true),
                occurrence: Some(0),
                obj_type: Some(11),
                ..
            }
        ));
        assert!(matches!(
            &lp.ops[1],
            LoadOp::WriteProp {
                verify: Some(false),
                count: None,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn test_parse_task_ptr_and_task_ctrl2() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let xml = br#"<KNX xmlns="http://knx.org/xml/project/20"><ApplicationProgram Id="M-00FA_A-0003" MaskVersion="MV-0701">
          <Static><LoadProcedures><LoadProcedure>
            <LdCtrlTaskPtr LsmIdx="3" InitPtr="284" SavePtr="285" SerialPtr="0" />
            <LdCtrlTaskCtrl2 LsmIdx="3" Callback="20609" Address="282" Seg0="208" Seg1="200" />
          </LoadProcedure></LoadProcedures></Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-00FA_A-0003", &xml[..])?;
        let ops = &app.load_procedures.first().ok_or("a procedure")?.ops;
        assert!(matches!(
            ops[0],
            LoadOp::TaskPtr {
                lsm_idx: Some(3),
                init_ptr: Some(284),
                save_ptr: Some(285),
                serial_ptr: Some(0),
            }
        ));
        assert!(matches!(
            ops[1],
            LoadOp::TaskCtrl2 {
                lsm_idx: Some(3),
                callback: Some(20609),
                address: Some(282),
                seg0: Some(208),
                seg1: Some(200),
            }
        ));
        Ok(())
    }
}
