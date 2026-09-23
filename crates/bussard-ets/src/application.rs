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
//! Everything is keyed by full XML `Id`, so refs resolve by lookup. English
//! (`en-US`) translations from the file's `<Languages>` section override the
//! default-language `Name`/`Text` attributes, matching ETS behaviour.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::attrs::{Attrs, flagset_from, get};
use crate::dpt::parse_ets_dpt;
use crate::error::{EtsError, Result};
use crate::flags::FlagSet;
use crate::translation::TranslationCollector;
use bussard_model::Dpt;

/// A base `<ComObject>` from the application program.
#[derive(Debug, Clone, Default)]
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
    /// For a module com-object: the argument id (its `BaseNumber` attribute)
    /// whose value is added to `number` to compute the instance's effective
    /// object number.
    pub base_number_ref: Option<String>,
}

/// A `<ComObjectRef>` from the application program.
#[derive(Debug, Clone, Default)]
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
}

/// A `<Channel>` definition from the application program's Dynamic section.
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone, Default)]
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

/// The comparison a `<when test="!=0">`-style branch makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
}

impl CompareOp {
    /// Applies the comparison to a parameter value.
    pub fn matches(self, value: i64, against: i64) -> bool {
        match self {
            CompareOp::Ne => value != against,
            CompareOp::Lt => value < against,
            CompareOp::Le => value <= against,
            CompareOp::Gt => value > against,
            CompareOp::Ge => value >= against,
        }
    }
}

/// The condition on one `<when>` branch of a `<choose>`.
///
/// ETS writes four shapes, all of which occur in real product data (counted over
/// the 495-product corpus in `tests-support/product-corpus`):
///
/// * `test="1"` and `test="0 2"` — one or more exact values ([`WhenTest::Values`],
///   8.2 M and 492 k occurrences). A value may be negative (`test="-1"`).
/// * `test="!=0"`, `test=">=2"`, `test="<3"` — a comparison
///   ([`WhenTest::Compare`], ~130 k).
/// * `<when default="true">` — the branch taken when no sibling matched
///   ([`WhenTest::Default`], 97 k).
/// * anything else, preserved verbatim ([`WhenTest::Unknown`]) rather than
///   silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenTest {
    /// One or more exact values; the branch applies when the parameter takes any
    /// of them.
    Values(Vec<i64>),
    /// A comparison against a single value.
    Compare {
        /// The comparison operator.
        op: CompareOp,
        /// The right-hand side.
        value: i64,
    },
    /// `<when default="true">`: applies when no other branch of the `<choose>`
    /// matched.
    Default,
    /// A `test` expression bussard does not understand, kept as written so it is
    /// visible rather than silently treated as unconditional.
    Unknown(String),
}

impl WhenTest {
    /// Parses a `<when>` element's `test` / `default` attributes.
    ///
    /// `default="true"` wins over a `test` (a branch that declares both is the
    /// default branch). An absent `test` with no `default` is [`WhenTest::Unknown`]
    /// with an empty expression: it matches nothing, which is safer than the old
    /// behaviour of treating the branch's members as unconditional.
    pub fn parse(test: Option<&str>, default: Option<&str>) -> Self {
        if matches!(default.map(str::trim), Some("true") | Some("1")) {
            return WhenTest::Default;
        }
        let raw = test.unwrap_or("").trim();
        if raw.is_empty() {
            return WhenTest::Unknown(String::new());
        }
        // A comparison is a single token; an exact set is whitespace separated.
        for (prefix, op) in [
            ("!=", CompareOp::Ne),
            ("<=", CompareOp::Le),
            (">=", CompareOp::Ge),
            ("<", CompareOp::Lt),
            (">", CompareOp::Gt),
        ] {
            if let Some(rest) = raw.strip_prefix(prefix) {
                return match rest.trim().parse::<i64>() {
                    Ok(value) => WhenTest::Compare { op, value },
                    Err(_) => WhenTest::Unknown(raw.to_string()),
                };
            }
        }
        let mut values = Vec::new();
        for token in raw.split_whitespace() {
            match token.parse::<i64>() {
                Ok(v) => values.push(v),
                Err(_) => return WhenTest::Unknown(raw.to_string()),
            }
        }
        WhenTest::Values(values)
    }

    /// Whether this branch applies to a parameter value.
    ///
    /// [`WhenTest::Default`] and [`WhenTest::Unknown`] never match directly; the
    /// default branch is chosen by [`ConditionalGroup::members_for`] when nothing
    /// else matched.
    pub fn matches(&self, value: i64) -> bool {
        match self {
            WhenTest::Values(vs) => vs.contains(&value),
            WhenTest::Compare { op, value: against } => op.matches(value, *against),
            WhenTest::Default | WhenTest::Unknown(_) => false,
        }
    }
}

/// One `<when>` branch of a `<choose>`: its condition and the com-object-ref ids
/// it contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhenBranch {
    /// The branch condition.
    pub test: WhenTest,
    /// The com-object-ref ids collected directly inside this branch.
    pub members: Vec<String>,
}

/// One `<choose>/<when>` conditional group inside a [`ChannelMembership`].
#[derive(Debug, Clone, Default)]
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

/// One node of an application program's Dynamic section, kept as a tree so the
/// section can be evaluated against a device's parameter values (see
/// [`crate::dynamic::evaluate_dynamic`]).
///
/// Containers that carry no condition (`<ChannelIndependentBlock>`,
/// `<Channel>`, `<ParameterBlock>`, `<Rows>`/`<Columns>`) are flattened into
/// their parent: only what decides visibility and what it makes visible is
/// kept. All ids are app-relative (the program-id prefix stripped).
#[derive(Debug, Clone, PartialEq)]
pub enum DynamicNode {
    /// `<ParameterRefRef RefId>`: the parameter ref is shown (and its memory
    /// written) when this node is reached.
    ParameterRefRef(String),
    /// `<ComObjectRefRef RefId>`: the com-object ref is instantiated when this
    /// node is reached.
    ComObjectRefRef(String),
    /// `<choose ParamRefId>`: the branches whose test matches the parameter's
    /// value are evaluated (the `default` branches when none matches).
    Choose {
        /// The `ParameterRef` id whose value selects the branches.
        param_ref_id: String,
        /// The `<when>` branches in document order.
        whens: Vec<DynamicWhen>,
    },
    /// `<Module RefId>`: one instantiation of a `<ModuleDef>`; reaching it
    /// evaluates that module definition's own Dynamic section with these
    /// argument values.
    Module {
        /// The module instance id (e.g. `MD-13_M-44`).
        id: String,
        /// The module definition it instantiates (e.g. `MD-13`).
        module_def: String,
        /// The `<NumericArg>` values, keyed by app-relative argument id.
        args: HashMap<String, i64>,
    },
    /// `<Assign TargetParamRefRef SourceParamRefRef|Value>`: while reached, the
    /// target parameter takes the source parameter's value (or the literal).
    Assign {
        /// The assigned `ParameterRef` id.
        target: String,
        /// The `ParameterRef` id whose value is copied, if any.
        source: Option<String>,
        /// The literal value assigned when there is no source.
        value: Option<String>,
    },
}

/// One `<when>` branch of a [`DynamicNode::Choose`].
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicWhen {
    /// The branch condition.
    pub test: WhenTest,
    /// The nodes evaluated when the branch is taken.
    pub children: Vec<DynamicNode>,
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

    /// The effective flags: base merged with the ref (ref wins per-flag).
    pub fn flags(&self) -> bussard_model::Flags {
        self.base.flags.merge(self.cref.flags).to_flags()
    }
}

/// A parameter type: the shape (int/enum/text/float/none) plus its size.
#[derive(Debug, Clone)]
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
        min: Option<f64>,
        /// Inclusive maximum, if declared.
        max: Option<f64>,
    },
    /// `<TypeNone>`: a marker type carrying no memory value.
    None,
    /// Any other type element (e.g. `TypeColor`, `TypeTime`, `TypePicture`),
    /// preserved by name so nothing is silently dropped.
    Other {
        /// The type element's local name, e.g. `"TypeTime"`.
        kind: String,
        /// Size in bits, if the element declared one.
        size_bits: Option<u32>,
    },
}

/// One `<Enumeration>` in a `<TypeRestriction>`.
#[derive(Debug, Clone)]
pub struct EnumValue {
    /// The numeric `Value`.
    pub value: i64,
    /// The display `Text`.
    pub text: String,
}

/// A named parameter type declaration (`<ParameterType>` wrapping one shape).
#[derive(Debug, Clone)]
pub struct ParameterTypeDecl {
    /// The full XML `Id`.
    pub id: String,
    /// The declared `Name`.
    pub name: Option<String>,
    /// The concrete shape.
    pub kind: ParameterType,
}

/// A `<Parameter>` definition.
#[derive(Debug, Clone, Default)]
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
}

/// A parameter's memory location (`<Memory CodeSegment Offset BitOffset>`).
#[derive(Debug, Clone, Default)]
pub struct Memory {
    /// The code-segment id this offset is relative/absolute to.
    pub code_segment: Option<String>,
    /// Byte offset within the segment.
    pub offset: Option<u32>,
    /// Bit offset within the byte.
    pub bit_offset: Option<u8>,
    /// For a **module** parameter, the module-`<Argument>` id whose per-instance
    /// value is *added* to [`offset`](Self::offset) to get that instance's
    /// effective byte offset (the `BaseOffset` attribute, e.g.
    /// `M-0004_A-1_MD-1_A-1` naming `MDA_P_Base`). This is the memory-offset
    /// analogue of a com-object's `BaseNumber`: the same module parameter is
    /// instantiated once per channel, and each instance places its value at
    /// `declared_offset + instance_argument[base_offset]`. `None` for a plain
    /// (non-module) parameter, whose declared offset is absolute within its
    /// segment. The per-instance argument value is not carried here — it lives in
    /// the project's `ModuleInstance` data — so this records only *that* a base is
    /// needed and *which* argument supplies it.
    pub base_offset: Option<String>,
}

/// A `<Union>` block: several parameters overlaying the same memory region.
///
/// A union declares one base location (its child `<Memory>`) and a `SizeInBit`
/// width, then lists member `<Parameter>`s whose `Offset`/`BitOffset` are
/// **relative within the union block** (not segment offsets). All members share
/// the same underlying bytes; ETS writes the value of the member marked
/// `DefaultUnionParameter` (falling back to the first member when none is
/// marked). See [`UnionMember`] and `bussard_prod`'s image computation, which
/// lays the default member down at `union_base + member_offset`.
#[derive(Debug, Clone, Default)]
pub struct Union {
    /// The union's `SizeInBit` (the size of the shared region), if declared.
    pub size_bits: Option<u32>,
    /// The base memory location (the union's single `<Memory>` child). Member
    /// offsets are added to this location's `offset`.
    pub memory: Option<Memory>,
    /// The member parameters overlaying the region, in document order.
    pub members: Vec<UnionMember>,
}

/// One member of a [`Union`]: a parameter plus its position within the block.
#[derive(Debug, Clone, Default)]
pub struct UnionMember {
    /// The member parameter's full XML `Id` (also present in
    /// [`ApplicationProgram::parameters`], so its type/default resolve normally).
    pub parameter: String,
    /// Byte offset **relative to the union base**, from the member's `Offset`.
    pub offset: Option<u32>,
    /// Bit offset within the byte, from the member's `BitOffset`.
    pub bit_offset: Option<u8>,
    /// Whether this member is the union's `DefaultUnionParameter` (the value ETS
    /// lays into the shared memory). `true` for `DefaultUnionParameter="1"` or
    /// `"true"`.
    pub is_default: bool,
}

/// A `<ParameterRef>`: a reference to a [`Parameter`] with optional overrides.
#[derive(Debug, Clone, Default)]
pub struct ParameterRef {
    /// The full XML `Id`.
    pub id: String,
    /// The `Parameter` id this ref points at.
    pub ref_id: String,
    /// A `Value` override, if present.
    pub value: Option<String>,
    /// An `Access` override, if present.
    pub access: Option<String>,
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    /// A `<RelativeSegment>`.
    Relative,
    /// An `<AbsoluteSegment>`.
    Absolute,
}

/// One step of a load procedure, a faithful (uninterpreted) representation of an
/// `LdCtrl*` element. Known control ops get a typed variant carrying the
/// attributes phase-3 (`bussard-download`) will need; unrecognized ops are kept
/// verbatim as [`LoadOp::Raw`] so nothing is lost.
#[derive(Debug, Clone)]
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
    /// `<LdCtrlRelSegment …>`: a relative-segment control op.
    RelSegment {
        /// Load-state-machine index.
        lsm_idx: Option<u32>,
        /// Declared size in bytes.
        size: Option<u32>,
        /// `AppliesTo` filter (e.g. `"full"`, `"par"`, `"full,par"`).
        applies_to: Option<String>,
        /// The device-side pre-fill the allocation requests, decoded from the
        /// op's `Mode` (fill flag) / `Fill` (fill byte) attributes, or the older
        /// `Fill` / `FillByte` spelling. `Some(b)` means the ETS procedure asks
        /// for the fill (`Mode="1"`) — the device pre-fills the freshly
        /// allocated segment with `b` before the writes land (the app-code
        /// segment on some products, e.g. Jung LED A-3030 obj4 alloc
        /// `030b000028c1 01 00 0000`). `None` means no fill was asked for
        /// (`Mode="0"`, or no fill attribute at all): the DA.tp behaviour
        /// bussard has always emitted.
        fill: Option<u8>,
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
#[derive(Debug, Clone, Default)]
pub struct LoadProcedure {
    /// The `MergeId`, if this is part of a merged procedure.
    pub merge_id: Option<String>,
    /// The ordered control operations.
    pub ops: Vec<LoadOp>,
}

/// One parsed ApplicationProgram.
#[derive(Debug, Clone, Default)]
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
    /// Application-program display name (en-US resolved).
    pub name: Option<String>,
    /// The declared `LoadProcedureStyle`.
    pub load_procedure_style: Option<String>,
    /// Whether the application declares `IsSecureEnabled="true"`: it is KNX
    /// Data-Secure-capable (issue #71, spec §11). Capability, not activation.
    pub is_secure_enabled: bool,
    /// The XML schema version this file declared, e.g. `"20"`, `"21"`, `"23"`.
    pub schema_version: Option<String>,
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
    /// Module `<Argument>` name → app-relative argument id (e.g.
    /// `ArgBeschriftung` → `MD-1_A-3`), used to resolve `{{Arg…}}` placeholders
    /// in channel and com-object texts against a module instance's values.
    pub argument_ids: HashMap<String, String>,
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
    let context = format!("application program {id}");
    // Strip a leading UTF-8 BOM on the bytes so the reader starts on `<`.
    let xml = xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml);
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut app = ApplicationProgram {
        id: id.to_string(),
        ..Default::default()
    };

    // en-US translations, applied after the main pass.
    let mut translations = TranslationCollector::new();

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
                }
                b"when" => {
                    // Close the innermost `<when>`: attach its collected
                    // com-object-ref ids to its own `<choose>` frame.
                    if let Some(frame) = state.dynamic.choose_stack.last_mut() {
                        if let Some(branch) = frame.when.take() {
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
                }
                b"choose" => {
                    // Pop the innermost `<choose>` and attach it to the
                    // membership. A nested group is attached in its own right:
                    // the flat membership cannot express "inner branch AND outer
                    // branch", but each group keeps its own members.
                    if let Some(frame) = state.dynamic.choose_stack.pop() {
                        if let Some(mem) = state.dynamic.cur_membership.as_mut() {
                            mem.conditional.push(frame.group);
                        }
                    }
                }
                b"ParameterBlock" => {
                    // Close the channel parameter block: capture its membership
                    // once (a module template has a single channel/block).
                    if let Some(mem) = state.dynamic.cur_membership.take() {
                        if !state.dynamic.membership_captured {
                            app.channel_membership = Some(mem);
                            state.dynamic.membership_captured = true;
                        }
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
    Ok(app)
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
            app.name = get(m, b"Name").map(str::to_string);
            app.load_procedure_style = get(m, b"LoadProcedureStyle").map(str::to_string);
            // KNX Secure capability (issue #71, spec §11): the application
            // declares whether it can run Data Secure. Preserve it (previously
            // dropped); it is a capability flag, not key material.
            app.is_secure_enabled = get(m, b"IsSecureEnabled")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
        }
        b"RelativeSegment" => insert_segment(app, m, SegmentKind::Relative),
        b"AbsoluteSegment" => insert_segment(app, m, SegmentKind::Absolute),
        b"Language" => translations.enter_language(get(m, b"Identifier")),
        b"TranslationElement" => translations.enter_element(get(m, b"RefId")),
        b"ComObject" => insert_com_object(app, m),
        b"ComObjectRef" => insert_com_object_ref(app, m),
        b"Channel" => insert_channel(app, m),
        b"Argument" => insert_argument(app, m),
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
                ops: Vec::new(),
            });
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
        }
        _ => {}
    }

    // A `<Translation>` may appear as a Start with a nested value; capture attr.
    if e.local_name().as_ref() == b"Translation" {
        translations.record(m, &["Name", "Text"]);
    }
    Ok(())
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
        b"NumericArg" => {
            // A `<NumericArg RefId=arg-id Value=n>` of the current `<Module>`.
            if let Some(module) = state.dynamic.cur_module.as_mut() {
                if let (Some(arg_id), Some(value)) = (
                    get(m, b"RefId").and_then(|id| app_relative_id(id, &app.id)),
                    get(m, b"Value").and_then(|s| s.parse::<i64>().ok()),
                ) {
                    module.arg_values.insert(arg_id.to_string(), value);
                }
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
            if let Some(mem) = state.dynamic.cur_membership.as_mut() {
                if let Some(ref_id) = get(m, b"RefId").and_then(|id| app_relative_id(id, &app.id)) {
                    mem.parameter_refs.push(ref_id.to_string());
                }
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
        b"TranslationElement" => translations.enter_element(get(m, b"RefId")),
        b"Translation" => translations.record(m, &["Name", "Text"]),
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
            if let Some(ParameterType::Enum { values, .. }) = state.pt_kind.as_mut() {
                if let (Some(value), Some(text)) = (
                    get(m, b"Value").and_then(|s| s.parse::<i64>().ok()),
                    get(m, b"Text"),
                ) {
                    values.push(EnumValue {
                        value,
                        text: text.to_string(),
                    });
                }
            }
        }
        b"RelativeSegment" => insert_segment(app, m, SegmentKind::Relative),
        b"AbsoluteSegment" => insert_segment(app, m, SegmentKind::Absolute),
        name if name.starts_with(b"Type") => {
            // Other type shapes (TypeColor, TypeTime, TypePicture, TypeIPAddress…).
            let kind = String::from_utf8_lossy(name).into_owned();
            state.pt_kind = Some(ParameterType::Other {
                kind,
                size_bits: get(m, b"SizeInBit").and_then(|s| s.parse().ok()),
            });
        }
        name if name.starts_with(b"LdCtrl") => {
            push_load_op(&mut state.lp, e, m);
        }
        _ => {}
    }
    Ok(())
}

/// Applies collected en-US translations to names/texts.
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
    }
    for (id, cref) in app.com_object_refs.iter_mut() {
        if let Some(t) = translations.get(id, "Text") {
            cref.text = Some(t.to_string());
        }
    }
    for (id, param) in app.parameters.iter_mut() {
        if let Some(t) = translations.get(id, "Text") {
            param.text = Some(t.to_string());
        }
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
        },
    );
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
}

/// Records a module `<Argument>`'s name → app-relative id (first wins).
fn insert_argument(app: &mut ApplicationProgram, m: &Attrs) {
    let (Some(id), Some(name)) = (get(m, b"Id"), get(m, b"Name")) else {
        return;
    };
    if let Some(rel) = app_relative_id(id, &app.id) {
        app.argument_ids
            .entry(name.to_string())
            .or_insert_with(|| rel.to_string());
    }
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
    /// The app-relative id of the `<ModuleDef>` currently open, if any.
    module_def: Option<String>,
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
    },
}

impl DynTreeBuilder {
    /// Appends a finished node to the innermost frame that holds children.
    fn push_node(&mut self, node: DynamicNode) {
        match self.frames.last_mut() {
            Some(DynFrame::Root(children)) | Some(DynFrame::When(DynamicWhen { children, .. })) => {
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
                b"ModuleDef" => self.module_def = Some(rel(b"Id")),
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
            }),
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
                if let Some(DynFrame::Module { args, .. }) = self.frames.last_mut() {
                    if let (Some(arg), Some(value)) = (
                        get(m, b"RefId").map(|id| app_relative_id(id, app_id).unwrap_or(id)),
                        get(m, b"Value").and_then(|v| v.trim().parse::<i64>().ok()),
                    ) {
                        args.insert(arg.to_string(), value);
                    }
                }
            }
            b"when" | b"choose" | b"Module" => {
                // An empty branch, choose or argument-less module: open and
                // close it at once.
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
            b"ModuleDef" if self.frames.is_empty() => self.module_def = None,
            b"when" => {
                if let Some(DynFrame::When(_)) = self.frames.last() {
                    if let Some(DynFrame::When(branch)) = self.frames.pop() {
                        if let Some(DynFrame::Choose { whens, .. }) = self.frames.last_mut() {
                            whens.push(branch);
                        }
                    }
                }
            }
            b"choose" => {
                if let Some(DynFrame::Choose { .. }) = self.frames.last() {
                    if let Some(DynFrame::Choose {
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
            }
            b"Module" => {
                if let Some(DynFrame::Module { .. }) = self.frames.last() {
                    if let Some(DynFrame::Module {
                        id,
                        module_def,
                        args,
                    }) = self.frames.pop()
                    {
                        self.push_node(DynamicNode::Module {
                            id,
                            module_def,
                            args,
                        });
                    }
                }
            }
            b"Dynamic" => {
                // Unwind whatever malformed XML left open, then store the root.
                while self.frames.len() > 1 {
                    self.frames.pop();
                }
                if let (Some(DynFrame::Root(children)), Some(app)) = (self.frames.pop(), app) {
                    match &self.module_def {
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
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Decodes a `LdCtrlRelSegment`'s fill attributes into the pre-fill value to
/// request.
///
/// The KNX schema spells the allocation's fill as `Mode` (the fill flag: `1`
/// pre-fills the freshly allocated segment, `0` does not) plus `Fill` (the fill
/// byte). A real Jung F50 procedure reads
/// `<LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6152" Mode="1" Fill="0"/>`
/// and ETS sends `03 0b 00 00 18 08 01 00 00 00` for it: flag set, byte `00`
/// (issue #123). So when `Mode` is present it decides: non-zero → `Some(Fill)`
/// (`Fill` defaulting to `0`), zero → `None`.
///
/// Without a `Mode` attribute the older reading applies: `Fill="1"`/`"true"` is
/// the flag and `FillByte` the byte (decimal or `0x` hex, default `0`). Any
/// other value, or no attribute at all, means no pre-fill (the DA.tp shape,
/// byte-identical to the historical no-fill allocation).
fn parse_fill(m: &Attrs) -> Option<u8> {
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
        let on = mode.trim().parse::<u8>().map(|v| v != 0).unwrap_or(false);
        return on.then(|| byte(get(m, b"Fill")));
    }
    let raw = get(m, b"Fill")?;
    let on = matches!(raw.trim(), "1" | "true" | "True" | "TRUE");
    if !on {
        return None;
    }
    Some(byte(get(m, b"FillByte")))
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
        },
        b"LdCtrlCompareProp" => LoadOp::CompareProp {
            obj_idx: u(b"ObjIdx"),
            obj_type: u(b"ObjType"),
            prop_id: u(b"PropId"),
            inline_data: get(m, b"InlineData").and_then(decode_hex_bytes),
            mask: get(m, b"Mask").and_then(decode_hex_bytes),
            range: s(b"Range"),
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
        other => LoadOp::Raw {
            name: String::from_utf8_lossy(other).into_owned(),
            attrs: ordered_attrs(m),
        },
    };
    lp.ops.push(op);
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

    fn sample() -> ApplicationProgram {
        parse_application_program_str("M-00FA_A-1", SAMPLE).unwrap()
    }

    #[test]
    fn parses_identity_and_schema() {
        let app = sample();
        assert_eq!(app.application_number, Some(7));
        assert_eq!(app.application_version, Some(17));
        assert_eq!(app.version.as_deref(), Some("17"));
        assert_eq!(app.mask_version.as_deref(), Some("07B0"));
        assert_eq!(app.name.as_deref(), Some("Sample"));
        assert_eq!(app.load_procedure_style.as_deref(), Some("MergedProcedure"));
        assert_eq!(app.schema_version.as_deref(), Some("23"));
    }

    #[test]
    fn resolves_com_objects_with_dpt_and_flags() {
        let app = sample();
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
    }

    #[test]
    fn resolve_instance_ref() {
        let app = sample();
        let (base, cor) = app.resolve("O-0_R-1").unwrap();
        assert_eq!(base.number, 0);
        assert_eq!(cor.dpt, Some(Dpt::new(1, Some(1))));
        assert_eq!(base.flags.merge(cor.flags).to_flags().to_string(), "CRWT");
    }

    #[test]
    fn parses_all_parameter_type_kinds() {
        let app = sample();
        let kind = |id: &str| &app.parameter_types.get(id).unwrap().kind;
        assert!(matches!(
            kind("M-00FA_A-1_PT-int"),
            ParameterType::Int {
                min: Some(0),
                max: Some(100),
                size_bits: Some(8),
                signed: false
            }
        ));
        assert!(matches!(
            kind("M-00FA_A-1_PT-sint"),
            ParameterType::Int { signed: true, .. }
        ));
        match kind("M-00FA_A-1_PT-enum") {
            ParameterType::Enum { values, .. } => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].value, 0);
                assert_eq!(values[0].text, "Off");
            }
            other => panic!("expected enum, got {other:?}"),
        }
        assert!(matches!(
            kind("M-00FA_A-1_PT-txt"),
            ParameterType::Text {
                size_bits: Some(112)
            }
        ));
        assert!(matches!(
            kind("M-00FA_A-1_PT-flt"),
            ParameterType::Float {
                min: Some(_),
                max: Some(_),
                ..
            }
        ));
        assert!(matches!(kind("M-00FA_A-1_PT-none"), ParameterType::None));
        match kind("M-00FA_A-1_PT-col") {
            ParameterType::Other { kind, .. } => assert_eq!(kind, "TypeColor"),
            other => panic!("expected other, got {other:?}"),
        }
    }

    #[test]
    fn parameter_ref_value_override_applies() {
        let app = sample();
        let rp = app.resolved_parameter("M-00FA_A-1_P-1_R-1").unwrap();
        // The parameter's own default is 50; the ref overrides it to 75.
        assert_eq!(rp.value(), Some("75"));
        // P-2's ref overrides Access to None.
        let rp2 = app.resolved_parameter("M-00FA_A-1_P-2_R-1").unwrap();
        assert_eq!(rp2.access(), Some("None"));
    }

    #[test]
    fn parses_memory_location() {
        let app = sample();
        let mem = app
            .parameters
            .get("M-00FA_A-1_P-1")
            .unwrap()
            .memory
            .as_ref()
            .unwrap();
        assert_eq!(mem.code_segment.as_deref(), Some("M-00FA_A-1_RS-4"));
        assert_eq!(mem.offset, Some(3));
        assert_eq!(mem.bit_offset, Some(2));
        // A parameter with no <Memory> child has None.
        assert!(
            app.parameters
                .get("M-00FA_A-1_P-2")
                .unwrap()
                .memory
                .is_none()
        );
    }

    #[test]
    fn parses_code_segments_with_inline_data() {
        let app = sample();
        assert_eq!(app.code_segments.len(), 2);
        let rel = app.code_segments.get("M-00FA_A-1_RS-4").unwrap();
        assert_eq!(rel.kind, SegmentKind::Relative);
        assert_eq!(rel.size, Some(10));
        assert_eq!(rel.load_state_machine, Some(4));
        assert_eq!(rel.address_or_offset, Some(0));
        // The `<Data>` base64 decodes to the segment's image bytes and the
        // `<Mask>` to its parallel ownership mask.
        assert_eq!(rel.data.as_deref(), Some([0u8; 10].as_slice()));
        assert_eq!(rel.mask.as_deref(), Some([0xFFu8; 12].as_slice()));
        // The self-closing absolute segment stays metadata-only.
        let abs = app.code_segments.get("M-00FA_A-1_AS-1").unwrap();
        assert_eq!(abs.kind, SegmentKind::Absolute);
        assert_eq!(abs.address_or_offset, Some(16384));
        assert!(abs.data.is_none());
        assert!(abs.mask.is_none());
    }

    #[test]
    fn parses_every_load_op_variant() {
        let app = sample();
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
    }

    #[test]
    fn parses_load_image_prop_variants() {
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
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
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
    }

    #[test]
    fn parses_master_reset() {
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
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
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
    }

    #[test]
    fn test_push_load_op_rel_segment_fill_flag() {
        // The Jung LED A-3030 shape: the code segment (obj4) sets Fill="1" so the
        // device pre-fills the allocation (obj4 alloc `030b000028c1 01 00 0000`),
        // while the table objects keep Fill="0". A procedure with no `Fill`
        // attribute (the DA.tp shape) parses to `None` so the historical no-fill
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
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
        let ops = &app.load_procedures[0].ops;
        // Fill="1" with no FillByte → Some(0) (the Jung LED A-3030 code segment).
        assert!(matches!(
            ops[0],
            LoadOp::RelSegment {
                fill: Some(0),
                lsm_idx: Some(4),
                ..
            }
        ));
        // Fill="0" → None (no pre-fill).
        assert!(matches!(ops[1], LoadOp::RelSegment { fill: None, .. }));
        // Fill absent → None (the DA.tp default).
        assert!(matches!(ops[2], LoadOp::RelSegment { fill: None, .. }));
        // Fill="1" with an explicit hex FillByte.
        assert!(matches!(
            ops[3],
            LoadOp::RelSegment {
                fill: Some(0xAB),
                ..
            }
        ));
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
          </LoadProcedure></LoadProcedures>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml)?;
        let ops = &app.load_procedures[0].ops;
        assert!(matches!(ops[0], LoadOp::RelSegment { fill: Some(0), .. }));
        assert!(matches!(ops[1], LoadOp::RelSegment { fill: None, .. }));
        assert!(matches!(
            ops[2],
            LoadOp::RelSegment {
                fill: Some(0xFF),
                ..
            }
        ));
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
        assert_eq!(
            app.module_dynamics.get("MD-1"),
            Some(&vec![DynamicNode::ComObjectRefRef("MD-1_O-1_R-1".into())])
        );
        assert_eq!(app.dynamic.len(), 3);
        assert_eq!(
            app.dynamic[0],
            DynamicNode::ParameterRefRef("P-1_R-1".into())
        );
        let DynamicNode::Choose {
            param_ref_id,
            whens,
        } = &app.dynamic[1]
        else {
            panic!("expected a choose, got {:?}", app.dynamic[1]);
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
        } = &inner[0].children[0]
        else {
            panic!("expected a module");
        };
        assert_eq!((id.as_str(), module_def.as_str()), ("MD-1_M-3", "MD-1"));
        assert_eq!(args.get("MD-1_A-1"), Some(&65));
        assert!(
            matches!(&app.dynamic[2], DynamicNode::Assign { target, source: Some(src), .. }
            if target == "P-3_R-3" && src == "P-1_R-1")
        );
        assert_eq!(app.module_instances[0].id, "MD-1_M-3");
        Ok(())
    }

    #[test]
    fn parses_compare_prop_variants() {
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
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
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
    }

    #[test]
    fn en_us_translation_overrides_text() {
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
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
        assert_eq!(app.name.as_deref(), Some("English"));
        assert_eq!(
            app.com_objects.get("M-1_A-1_O-0").unwrap().text.as_deref(),
            Some("Switch")
        );
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
    fn parses_module_parameter_base_offset() {
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
        let app = parse_application_program_str("M-0004_A-1", xml).unwrap();
        let m = app
            .parameters
            .get("M-0004_A-1_MD-1_P-3")
            .unwrap()
            .memory
            .as_ref()
            .unwrap();
        assert_eq!(m.offset, Some(1));
        assert_eq!(m.base_offset.as_deref(), Some("M-0004_A-1_MD-1_A-1"));
        // The plain parameter has no BaseOffset.
        assert!(
            app.parameters
                .get("M-0004_A-1_P-9")
                .unwrap()
                .memory
                .as_ref()
                .unwrap()
                .base_offset
                .is_none()
        );
    }

    #[test]
    fn parses_union_block_members_and_default() {
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
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
        assert_eq!(app.unions.len(), 1);
        let u = &app.unions[0];
        assert_eq!(u.size_bits, Some(8));
        let mem = u.memory.as_ref().expect("union base memory");
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
                .unwrap()
                .default
                .as_deref(),
            Some("75")
        );
    }

    #[test]
    fn parses_union_default_true_spelling() {
        // ETS files spell the default flag as `"1"` or `"true"`; both must count.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" MaskVersion="MV-07B0" Name="x"><Static>
          <Union SizeInBit="8">
           <Memory CodeSegment="M-1_A-1_RS-1" Offset="10" BitOffset="0" />
           <Parameter Id="M-1_A-1_UP-1" Name="a" ParameterType="M-1_A-1_PT-0" Value="0" Offset="0" BitOffset="0" />
           <Parameter Id="M-1_A-1_UP-2" Name="b" DefaultUnionParameter="true" ParameterType="M-1_A-1_PT-0" Value="7" Offset="0" BitOffset="0" />
          </Union>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
        let u = &app.unions[0];
        assert!(!u.members[0].is_default);
        assert!(u.members[1].is_default, "\"true\" counts as default");
    }

    #[test]
    fn parses_channels_and_arguments() {
        let app = parse_application_program_str("M-0004_A-1", MODULE_SAMPLE).unwrap();
        let ch = app.channel("MD-1_CH-13").expect("channel def");
        assert_eq!(ch.name.as_deref(), Some("Relaisausgänge"));
        assert_eq!(
            ch.text.as_deref(),
            Some("{{ArgBeschriftungRelais}} {{ArgBeschriftung}} ({{0:...}})")
        );
        assert_eq!(app.argument_id("ArgBeschriftung"), Some("MD-1_A-3"));
        assert_eq!(app.argument_id("ArgBeschriftungRelais"), Some("MD-1_A-5"));
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
    fn test_parse_application_program_nested_choose_keeps_frames_apart() -> Result<()> {
        let app = parse_application_program_str("M-1_A-1", NESTED_CHOOSE_SAMPLE)?;
        let mem = app.channel_membership.as_ref().expect("channel membership");

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
            .expect("the test=\"1\" branch");
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
    fn test_parse_application_program_when_test_spellings() -> Result<()> {
        let app = parse_application_program_str("M-1_A-1", NESTED_CHOOSE_SAMPLE)?;
        let mem = app.channel_membership.as_ref().expect("channel membership");
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
    fn parses_base_number_ref() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <ApplicationProgram Id="M-1_A-1" Name="x">
            <Static><ComObjectTable>
              <ComObject Id="M-1_A-1_MD-1_O-2" Number="2" BaseNumber="M-1_A-1_MD-1_A-9" Text="Rel" CommunicationFlag="Enabled" />
            </ComObjectTable></Static>
          </ApplicationProgram>
        </KNX>"#;
        let app = parse_application_program_str("M-1_A-1", xml).unwrap();
        assert_eq!(
            app.com_objects
                .get("M-1_A-1_MD-1_O-2")
                .unwrap()
                .base_number_ref
                .as_deref(),
            Some("M-1_A-1_MD-1_A-9")
        );
    }

    #[test]
    fn invalid_segment_base64_reports_segment_decode() -> Result<()> {
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
        let err =
            parse_application_program_str("M-1_A-1", xml).expect_err("corrupt base64 must fail");
        match err {
            EtsError::SegmentDecode { segment, field, .. } => {
                assert_eq!(segment, "M-1_A-1_RS-4-1-0");
                assert_eq!(field, "Data");
            }
            other => panic!("expected SegmentDecode, got {other:?}"),
        }
        // The rendered message is actionable: it names the segment and field.
        let rendered = parse_application_program_str("M-1_A-1", xml)
            .expect_err("corrupt base64 must fail")
            .to_string();
        assert!(
            rendered.contains("M-1_A-1_RS-4-1-0") && rendered.contains("Data"),
            "message should name segment and field: {rendered}"
        );
        Ok(())
    }
}
