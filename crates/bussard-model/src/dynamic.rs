//! Evaluation of an application program's Dynamic section against a device's
//! parameter values.
//!
//! ETS decides what a device carries by walking the Dynamic section: a
//! `<choose ParamRefId>` takes the `<when>` branches whose test matches the
//! parameter's current value, a `<Module>` reached this way instantiates its
//! `<ModuleDef>` (evaluated again with the instance's argument values), and every
//! `<ParameterRefRef>` / `<ComObjectRefRef>` reached is part of the device's
//! configuration. Only those parameters are written into the parameter image
//! and only those com-objects get a group-object descriptor; everything behind a
//! branch that is not taken is left out.
//!
//! The evaluator reads its input through the [`DynamicSource`] trait, so the
//! same walk serves the product XML (`bussard_ets::ApplicationProgram`) and,
//! later, the product model (issue #345). [`evaluate_dynamic`] performs the
//! walk and returns a [`DynamicConfig`]: the reached module instances,
//! parameter refs and com-object refs, the reached containers, and the
//! resolved parameter values (overrides, `<Assign>` results, then the vendor
//! defaults). [`RefIndex`] is the value-free counterpart: every place a ref or
//! object occurs, with the gates in front of it.
//!
//! A `<Repeat>` instantiates its body as many times as its parameter's value
//! (or its `Count`) says, and an argument of a `<Module>` reached this way
//! may come from an `<Allocator>` (issue #449): each instance, in walk
//! order, takes the allocator's current value and advances it by the
//! argument's `Allocates`, plus the enclosing instance's `BaseValue`
//! argument. An application allocator counts across the whole walk, a
//! module definition's per instance of that definition (the DALI BOX v3's
//! channel 1 takes `Channel_params` `Start` 528, its scenes count from the
//! channel's own `Scene_params`). An argument whose allocator is exhausted or
//! unknown gets no value, so a location that needs it refuses instead of
//! falling back to 0. A repeated or nested instance gets its own key (see
//! [`ActiveModule::id`]), so its values are its own.
//!
//! `<Channel>` and `<ParameterBlock>` containers are transparent to the walk,
//! but it records where each reached item sits: its channel, its block path
//! and the module instance (with its ordinal) whose body contains it, in
//! [`DynamicConfig::parameter_placements`] and
//! [`DynamicConfig::com_object_placements`]. [`visible_parameter_refs`] picks
//! one ref per parameter from the result, and [`DynamicConfig::label`] reads a
//! `TextParameterRefId` label for [`crate::label::substitute_label`].
//!
//! A `<choose>` whose controlling parameter is itself inactive selects no
//! branch at all, not even a `<when default="true">` one (issue #159). ETS
//! decides activity by the same walk: a parameter is active while one of its
//! `<ParameterRefRef>`s is reached, i.e. its enclosing channel, parameter
//! block, `<when>` branch and module instance are all shown under the current
//! values. In the ETS schema a `<Channel>` or `<ParameterBlock>` is never
//! gated by an attribute of its own (its `Number`/`Text` only label it); it is
//! shown or hidden by the `<choose>`/`<when>` it sits in, and a module
//! instance is shown when its `<Module>` element is reached. So the reached
//! set of this walk is exactly the active set. Two cases stay active without
//! a reached `<ParameterRefRef>`: a parameter the Dynamic section never shows
//! anywhere (a pure steering parameter, which only ever has its value), and an
//! unreached `<Union>` member whose union has a reached member (its shared
//! memory is live, see `SharedUnions`). The target of a reached `<Assign>`
//! counts as active too: ETS writes it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

/// The application data the Dynamic evaluator reads.
///
/// All ids passed in and out are those of the source: `ParameterRef`,
/// module definition and argument ids app-relative (the program-id prefix
/// stripped, e.g. `P-3_R-5`, `MD-1`, `MD-1_A-2`), parameter ids in whatever
/// form the source keys its parameters by, used consistently across
/// [`Self::parameter_ref`], [`Self::parameter`], [`Self::integer_width`],
/// [`Self::enum_members`], [`Self::parameter_refs`] and [`UnionMember::parameter`].
pub trait DynamicSource {
    /// The application program id (e.g. `M-0002_A-A0ED-10-9B4E`); a
    /// `BaseValue` argument id carrying it as a prefix has it stripped.
    fn program_id(&self) -> &str;
    /// The application's own Dynamic section.
    fn dynamic(&self) -> &[DynamicNode];
    /// The Dynamic section of the module definition `module_def` (e.g. `MD-1`).
    fn module_dynamic(&self, module_def: &str) -> Option<&[DynamicNode]>;
    /// Every module definition with its Dynamic section, in any order.
    fn module_dynamics(&self) -> Box<dyn Iterator<Item = (&str, &[DynamicNode])> + '_>;
    /// (parameter id, ref `Value`) of an app-relative `ParameterRef` id.
    fn parameter_ref(&self, ref_id: &str) -> Option<(&str, Option<&str>)>;
    /// Every app-relative `ParameterRef` id with its parameter id, in any
    /// order.
    fn parameter_refs(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_>;
    /// (default `Value`, `BaseValue` argument id) of a parameter.
    fn parameter(&self, param_id: &str) -> Option<(Option<&str>, Option<&str>)>;
    /// Width in bits (1 to 64) and signedness of an integer or plain
    /// enumeration parameter, `None` for any other type (its shared union
    /// bits are not read back).
    fn integer_width(&self, param_id: &str) -> Option<(u32, bool)>;
    /// The members of an enumeration parameter, `None` for any other type:
    /// label-to-code for overrides and code-to-label for label texts.
    fn enum_members(&self, param_id: &str) -> Option<&[EnumValue]>;
    /// The application's `<Union>`s, in document order.
    fn unions(&self) -> &[Union];
    /// The `<Allocator>` with the app-relative id `allocator_id` (`L-2`, or
    /// `MD-1_L-1` for one a `<ModuleDef>` declares), `None` when the source
    /// declares none by that id (issue #449).
    fn allocator(&self, _allocator_id: &str) -> Option<Allocator> {
        None
    }
    /// The `Allocates` of the module `<Argument>` with the app-relative id
    /// `arg_id`: how far an allocator-fed value of the argument advances its
    /// allocator. `None` when the argument declares none.
    fn argument_allocates(&self, _arg_id: &str) -> Option<i64> {
        None
    }
}

impl<T: DynamicSource + ?Sized> DynamicSource for &T {
    fn program_id(&self) -> &str {
        (**self).program_id()
    }
    fn dynamic(&self) -> &[DynamicNode] {
        (**self).dynamic()
    }
    fn module_dynamic(&self, module_def: &str) -> Option<&[DynamicNode]> {
        (**self).module_dynamic(module_def)
    }
    fn module_dynamics(&self) -> Box<dyn Iterator<Item = (&str, &[DynamicNode])> + '_> {
        (**self).module_dynamics()
    }
    fn parameter_ref(&self, ref_id: &str) -> Option<(&str, Option<&str>)> {
        (**self).parameter_ref(ref_id)
    }
    fn parameter_refs(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        (**self).parameter_refs()
    }
    fn parameter(&self, param_id: &str) -> Option<(Option<&str>, Option<&str>)> {
        (**self).parameter(param_id)
    }
    fn integer_width(&self, param_id: &str) -> Option<(u32, bool)> {
        (**self).integer_width(param_id)
    }
    fn enum_members(&self, param_id: &str) -> Option<&[EnumValue]> {
        (**self).enum_members(param_id)
    }
    fn unions(&self) -> &[Union] {
        (**self).unions()
    }
    fn allocator(&self, allocator_id: &str) -> Option<Allocator> {
        (**self).allocator(allocator_id)
    }
    fn argument_allocates(&self, arg_id: &str) -> Option<i64> {
        (**self).argument_allocates(arg_id)
    }
}

/// An `<Allocator>`: a counter module instances draw argument values from
/// (issue #449). Each `<NumericArg AllocatorRefId>` of a reached instance
/// takes the allocator's current value, which then advances by the
/// argument's `Allocates`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Allocator {
    /// `Start`: the first value handed out.
    pub start: i64,
    /// `maxInclusive`: the last value the allocator may hand out, if declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inclusive: Option<i64>,
}

/// A `<NumericArg>` whose value is computed when its module is instantiated
/// (issue #449): drawn from an `<Allocator>` (`AllocatorRefId`), or a literal
/// `Value`, either one plus the enclosing instance's value of the argument
/// `BaseValue` names. A plain `Value` without `BaseValue` is kept in
/// [`DynamicNode::Module`]'s `args` instead.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputedArg {
    /// The argument id, app-relative (`MD-1_A-1`).
    pub arg: String,
    /// The `AllocatorRefId`, app-relative (`L-2`, `MD-1_L-1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocator: Option<String>,
    /// The literal `Value`, when the argument has no allocator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    /// The `BaseValue`: the app-relative id of an argument of the enclosing
    /// module instance whose value is added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

/// A `<Channel>` as a location in the Dynamic section: the channel an active
/// parameter or com-object sits in (see
/// [`Placement::channel`]), and the richer record kept for every
/// channel in `bussard_ets::ApplicationProgram::channel_refs`.
///
/// All ids are app-relative. For a channel of a module definition the id is the
/// definition's (`MD-1_CH-1`); the module instance is recorded next to it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChannelRef {
    /// The channel id, app-relative (e.g. `CH-2`, `MD-1_CH-1`).
    pub id: String,
    /// The `Number` attribute (the vendor's channel number), if present.
    pub number: Option<u32>,
    /// The `Name` attribute (the vendor's short label), if non-empty.
    pub name: Option<String>,
    /// The `Text` attribute (the display label, translation applied),
    /// which may carry `{{0:…}}` and `{{Arg…}}` placeholders.
    pub text: Option<String>,
    /// The `TextParameterRefId`, app-relative: the parameter ref whose value
    /// fills the text's `{{0}}` placeholder.
    pub text_parameter_ref: Option<String>,
}

/// A `<ParameterBlock>` as a location in the Dynamic section: one level of the
/// block path an active parameter or com-object sits in (see
/// [`Placement::blocks`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BlockRef {
    /// The block id, app-relative (e.g. `PB-13`, `MD-1_PB-2`).
    pub id: String,
    /// The `Name` attribute, if non-empty.
    pub name: Option<String>,
    /// The `Text` attribute (translation applied), if non-empty; may
    /// carry `{{0:…}}` and `{{Arg…}}` placeholders.
    pub text: Option<String>,
    /// The `TextParameterRefId`, app-relative: the parameter ref whose value
    /// fills the text's `{{0}}` placeholder.
    pub text_parameter_ref: Option<String>,
    /// The `ParamRefId`, app-relative: a block that is titled by a parameter
    /// ref (it has no `Text` of its own; ETS shows that ref's text).
    pub param_ref: Option<String>,
}

/// The comparison a `<when test="!=0">`-style branch makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// default branch is chosen by `bussard_ets::application::ConditionalGroup::members_for` when nothing
    /// else matched.
    pub fn matches(&self, value: i64) -> bool {
        match self {
            WhenTest::Values(vs) => vs.contains(&value),
            WhenTest::Compare { op, value: against } => op.matches(value, *against),
            WhenTest::Default | WhenTest::Unknown(_) => false,
        }
    }
}

/// One node of an application program's Dynamic section, kept as a tree so the
/// section can be evaluated against a device's parameter values (see
/// [`evaluate_dynamic`]).
///
/// `<Channel>` and `<ParameterBlock>` are kept as containers
/// ([`DynamicNode::Channel`], [`DynamicNode::ParameterBlock`]) so a walk knows
/// where each item sits; they carry no condition of their own, so evaluation
/// treats them transparently. A container left with no children is dropped.
/// The other unconditional containers (`<ChannelIndependentBlock>`,
/// `<Rows>`/`<Columns>`, …) are flattened into their parent.
/// [`flatten_containers`] gives the fully flattened view. All ids are
/// app-relative (the program-id prefix stripped).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum DynamicNode {
    /// `<Channel>`: a labelled group of the configuration.
    Channel {
        /// The channel id, app-relative (e.g. `MD-1_CH-1`).
        id: String,
        /// The `Name` attribute, if non-empty.
        name: Option<String>,
        /// The `Text` attribute (translation applied), if non-empty.
        text: Option<String>,
        /// The `Number` attribute.
        number: Option<u32>,
        /// The `TextParameterRefId`, app-relative.
        text_parameter_ref: Option<String>,
        /// The nodes inside the channel, in document order.
        children: Vec<DynamicNode>,
    },
    /// `<ParameterBlock>`: one page (or inline group) of parameters.
    ParameterBlock {
        /// The block id, app-relative (e.g. `PB-13`).
        id: String,
        /// The `Name` attribute, if non-empty.
        name: Option<String>,
        /// The `Text` attribute (translation applied), if non-empty.
        text: Option<String>,
        /// The `TextParameterRefId`, app-relative.
        text_parameter_ref: Option<String>,
        /// The `ParamRefId`, app-relative: the ref that titles a block without
        /// a `Text` of its own.
        param_ref: Option<String>,
        /// The nodes inside the block, in document order.
        children: Vec<DynamicNode>,
    },
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
        /// The `<NumericArg>` literal values, keyed by app-relative argument
        /// id.
        args: HashMap<String, i64>,
        /// The `<NumericArg>`s computed at instantiation (an allocator, or a
        /// `BaseValue`), in document order (issue #449).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        computed_args: Vec<ComputedArg>,
    },
    /// `<Repeat ParameterRefId|Count>`: the children are instantiated as many
    /// times as the parameter's value (or the literal `Count`) says, each
    /// `<Module>` inside once per repetition (issue #449).
    Repeat {
        /// The repeat id, app-relative (e.g. `X-1`, `MD-1_X-2`).
        id: String,
        /// The `ParameterRefId` whose value is the count, app-relative.
        param_ref_id: Option<String>,
        /// The literal `Count`, when there is no parameter.
        count: Option<u32>,
        /// The repeated nodes, in document order.
        children: Vec<DynamicNode>,
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

impl DynamicNode {
    /// The channel this node describes, if it is a [`DynamicNode::Channel`].
    pub fn channel_ref(&self) -> Option<ChannelRef> {
        match self {
            DynamicNode::Channel {
                id,
                name,
                text,
                number,
                text_parameter_ref,
                ..
            } => Some(ChannelRef {
                id: id.clone(),
                number: *number,
                name: name.clone(),
                text: text.clone(),
                text_parameter_ref: text_parameter_ref.clone(),
            }),
            _ => None,
        }
    }

    /// The block this node describes, if it is a
    /// [`DynamicNode::ParameterBlock`].
    pub fn block_ref(&self) -> Option<BlockRef> {
        match self {
            DynamicNode::ParameterBlock {
                id,
                name,
                text,
                text_parameter_ref,
                param_ref,
                ..
            } => Some(BlockRef {
                id: id.clone(),
                name: name.clone(),
                text: text.clone(),
                text_parameter_ref: text_parameter_ref.clone(),
                param_ref: param_ref.clone(),
            }),
            _ => None,
        }
    }
}

/// The Dynamic tree with every [`DynamicNode::Channel`] and
/// [`DynamicNode::ParameterBlock`] replaced by its children, recursively
/// (inside `<when>` branches too): the shape the parser produced before it
/// kept those containers.
pub fn flatten_containers(nodes: &[DynamicNode]) -> Vec<DynamicNode> {
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        match node {
            DynamicNode::Channel { children, .. }
            | DynamicNode::ParameterBlock { children, .. } => {
                out.extend(flatten_containers(children));
            }
            DynamicNode::Repeat {
                id,
                param_ref_id,
                count,
                children,
            } => out.push(DynamicNode::Repeat {
                id: id.clone(),
                param_ref_id: param_ref_id.clone(),
                count: *count,
                children: flatten_containers(children),
            }),
            DynamicNode::Choose {
                param_ref_id,
                whens,
            } => out.push(DynamicNode::Choose {
                param_ref_id: param_ref_id.clone(),
                whens: whens
                    .iter()
                    .map(|w| DynamicWhen {
                        test: w.test.clone(),
                        children: flatten_containers(&w.children),
                    })
                    .collect(),
            }),
            other => out.push(other.clone()),
        }
    }
    out
}

/// One `<when>` branch of a [`DynamicNode::Choose`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DynamicWhen {
    /// The branch condition.
    pub test: WhenTest,
    /// The nodes evaluated when the branch is taken.
    pub children: Vec<DynamicNode>,
}

/// One `<Enumeration>` in a `<TypeRestriction>`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnumValue {
    /// The numeric `Value`.
    pub value: i64,
    /// The display `Text` (translation applied): the label in the language
    /// the program was parsed in (see `bussard_ets::parse_application_program_in`).
    pub text: String,
    /// The untranslated `Text`: the label in the program's
    /// `DefaultLanguage`.
    #[serde(default)]
    pub default_text: String,
    /// The member's label in every translation layer the program carries,
    /// keyed by language identifier (e.g. `de-DE`). Lets a label written in
    /// another language than the parse language still name its member.
    #[serde(default)]
    pub translations: BTreeMap<String, String>,
    /// The `Id`, which a translation refers to.
    pub id: Option<String>,
    /// The decoded `BinaryValue` of a `<TypeRestriction Base="BinaryValue">`
    /// member: the octets ETS writes to memory for it, in place of `Value`
    /// (the ABB BE/S16's `…Select` parameters: `Value="0"`,
    /// `BinaryValue="4AY="`, ETS writes `e0 06`). `None` for a `Base="Value"`
    /// enumeration.
    pub binary_value: Option<Vec<u8>>,
}

/// How [`enum_member_by_label`] settled a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelMatch {
    /// Exactly one member carries the label: its `Value`.
    Member(i64),
    /// Several members carry it in the first language that knows it.
    Ambiguous,
    /// No member carries it in any language.
    Unknown,
}

/// The enumeration member a device file names by its label `text` (trimmed).
///
/// `bussard import` writes a member by its label in the project language
/// (the `language` in `bussard.lock`), and the flash, plan and apply paths
/// parse the product in that same language, so the label is matched against,
/// in order:
///
/// 1. [`EnumValue::text`], the label in the language the program was parsed
///    in,
/// 2. [`EnumValue::default_text`], the program's untranslated label,
/// 3. every translation layer ([`EnumValue::translations`]), so a device
///    file edited from a catalogue in another language still loads.
///
/// The first tier with a hit decides: a label two members share there is
/// [`LabelMatch::Ambiguous`] and never falls through to a later tier.
pub fn enum_member_by_label(values: &[EnumValue], text: &str) -> LabelMatch {
    let text = text.trim();
    let tiers: [&dyn Fn(&EnumValue) -> bool; 3] = [
        &|e| e.text.trim() == text,
        &|e| e.default_text.trim() == text,
        &|e| e.translations.values().any(|t| t.trim() == text),
    ];
    for matches in tiers {
        let mut codes: Vec<i64> = values
            .iter()
            .filter(|e| matches(e))
            .map(|e| e.value)
            .collect();
        codes.sort_unstable();
        codes.dedup();
        match codes.as_slice() {
            [] => continue,
            [one] => return LabelMatch::Member(*one),
            _ => return LabelMatch::Ambiguous,
        }
    }
    LabelMatch::Unknown
}

/// A parameter's memory location (`<Memory CodeSegment Offset BitOffset>`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UnionMember {
    /// The member parameter's full XML `Id` (also present in
    /// `bussard_ets::ApplicationProgram::parameters`, so its type/default resolve normally).
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

/// How deep `<Module>` instantiations may nest before the walk stops (real
/// products nest at most one level; the bound only guards a malformed file).
const MAX_MODULE_DEPTH: usize = 8;

/// How many times the walk is repeated to settle `<Assign>` results that feed
/// back into `<choose>` decisions.
const MAX_ASSIGN_PASSES: usize = 16;

/// One module instance the walk reached.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveModule {
    /// The instance key, app-relative: the `<Module>` id (e.g. `MD-13_M-44`)
    /// for a module instantiated once; with the repetition appended
    /// (`MD-1_M-1_MI-2`) for the second and later instance of a `<Repeat>`;
    /// and for a submodule its parent's [`Self::selector`] followed by the
    /// submodule's `<Module>` id without the shared `MD-<d>_` and its own
    /// repetition (`MD-1_M-1_MI-1_SM-1_M-1_MI-3`). Values are keyed by it, and
    /// [`selector_key`] / [`split_selector`] convert to and from the device
    /// key form.
    pub id: String,
    /// The `<Module>` element's own id (`MD-13_M-44`, `MD-1_SM-1_M-1`).
    pub element_id: String,
    /// The module definition it instantiates (e.g. `MD-13`).
    pub module_def: String,
    /// The instance's argument values, keyed by app-relative argument id:
    /// the literal `<NumericArg>`s and the computed ones that resolved (an
    /// allocator-fed argument past its allocator's `maxInclusive`, or one
    /// whose `BaseValue` names an argument the parent lacks, is absent, so a
    /// location that needs it refuses; issue #449).
    pub args: HashMap<String, i64>,
    /// Index into [`DynamicConfig::modules`] of the instance whose body
    /// holds this one's `<Module>` element, `None` at the application level.
    pub parent: Option<usize>,
    /// The 1-based repetition of the enclosing `<Repeat>` this instance was
    /// made in (the project's `_MI-<n>`), 1 outside any `<Repeat>`.
    pub repetition: u32,
    /// The instance's 1-based ordinal among all instances of the same module
    /// definition, in `M-<m>` order (by the numeric `m`). Counted over every
    /// `<Module>` element of the application, reached or not, so it is stable
    /// under parameter changes; a repetition `n` of a `<Repeat>` adds `n - 1`.
    pub ordinal: u32,
}

impl ActiveModule {
    /// The instance's module-instance selector in the device key form: the
    /// key itself when it carries its `_MI-<n>`, else the key with `_MI-1`
    /// (`MD-1_M-3` gives `MD-1_M-3_MI-1`).
    pub fn selector(&self) -> String {
        if self.id.contains("_MI-") {
            self.id.clone()
        } else {
            format!("{}_MI-1", self.id)
        }
    }
}

/// Where an active parameter or com-object sits in the Dynamic section.
///
/// [`DynamicConfig::parameter_placements`] and
/// [`DynamicConfig::com_object_placements`] hold one per entry of
/// [`DynamicConfig::parameters`] and [`DynamicConfig::com_objects`], at the
/// same index. The placement is that of the first reach of the entry in walk
/// (document) order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Placement {
    /// The enclosing `<Channel>`, if any.
    pub channel: Option<ChannelRef>,
    /// The enclosing `<ParameterBlock>`s, outermost first.
    pub blocks: Vec<BlockRef>,
    /// Index into [`DynamicConfig::modules`] of the module instance whose
    /// Dynamic body contains the element, `None` at the application level.
    /// This is where the element sits, which can differ from the scope of an
    /// application ref reached inside a module body (see
    /// [`ActiveParameter::module`]).
    pub module: Option<usize>,
    /// The id of that module instance (e.g. `MD-1_M-3`).
    pub module_instance: Option<String>,
    /// That instance's ordinal ([`ActiveModule::ordinal`]).
    pub module_ordinal: Option<u32>,
    /// Whether the entry was reached through a `<ParameterRefRef>` or
    /// `<ComObjectRefRef>` (shown in ETS). `false` for a parameter that is
    /// only the target or source of a reached `<Assign>`; its channel and
    /// blocks are then those of the `<Assign>` element.
    pub shown: bool,
}

/// The location context while walking: the enclosing channel and block path.
#[derive(Debug, Default)]
struct Context {
    channel: Option<ChannelRef>,
    blocks: Vec<BlockRef>,
}

/// Where a walk reached an item: the shared context plus the enclosing module.
#[derive(Debug, Clone, Default)]
struct Place {
    ctx: Rc<Context>,
    module: Option<usize>,
}

/// A parameter ref the walk reached (shown in ETS, so written to memory).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActiveParameter {
    /// Index into [`DynamicConfig::modules`] of the module instance the ref
    /// belongs to; `None` for a parameter of the application itself.
    pub module: Option<usize>,
    /// The app-relative `ParameterRef` id (e.g. `MD-3_P-3_R-6`).
    pub param_ref_id: String,
}

/// A com-object ref the walk reached (instantiated on the device).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActiveComObject {
    /// Index into [`DynamicConfig::modules`] of the module instance; `None`
    /// for a com-object of the application itself.
    pub module: Option<usize>,
    /// The app-relative `ComObjectRef` id (e.g. `MD-3_O-2-0_R-1`).
    pub com_object_ref_id: String,
}

/// The result of evaluating an application's Dynamic section.
#[derive(Debug, Clone, Default)]
pub struct DynamicConfig {
    /// The module instances reached, in walk order.
    pub modules: Vec<ActiveModule>,
    /// The parameter refs reached, in walk order and without duplicates:
    /// every `<ParameterRefRef>` plus the target and source of every reached
    /// `<Assign>` (ETS writes both).
    pub parameters: Vec<ActiveParameter>,
    /// The com-object refs reached, in walk order and without duplicates.
    pub com_objects: Vec<ActiveComObject>,
    /// Where each entry of [`Self::parameters`] sits, at the same index.
    pub parameter_placements: Vec<Placement>,
    /// Where each entry of [`Self::com_objects`] sits, at the same index.
    pub com_object_placements: Vec<Placement>,
    /// Every `<Channel>` and `<ParameterBlock>` the walk entered, in walk
    /// order, once per (module instance, id).
    pub containers: Vec<ActiveContainer>,
    /// Override keys that name no `ParameterRef` of this application.
    pub unresolved_overrides: Vec<String>,
    /// Resolved values keyed by (module instance id or `""`, app-relative
    /// `ParameterRef` id): the overrides and the `<Assign>` results.
    values: HashMap<(String, String), String>,
    /// The keys of `values` that came from a caller override (not an assign).
    overridden: HashSet<(String, String)>,
}

impl DynamicConfig {
    /// The argument values of the module instance `module` (empty for the
    /// application itself).
    pub fn module_args(&self, module: Option<usize>) -> Option<&HashMap<String, i64>> {
        module.and_then(|i| self.modules.get(i)).map(|m| &m.args)
    }

    /// The effective value of `param_ref_id` (app-relative) in the context of
    /// `module`: an override or `<Assign>` result for this ref, else the ref's
    /// `Value`, else the parameter's own `Value`.
    pub fn value<S: DynamicSource + ?Sized>(
        &self,
        app: &S,
        module: Option<usize>,
        param_ref_id: &str,
    ) -> Option<String> {
        value_of(
            app,
            &self.values,
            self.instance_id(module),
            self.module_args(module),
            param_ref_id,
        )
    }

    /// Whether the value of `param_ref_id` in `module` came from a caller
    /// override (as opposed to a vendor default or an `<Assign>`).
    pub fn is_override<S: DynamicSource + ?Sized>(
        &self,
        app: &S,
        module: Option<usize>,
        param_ref_id: &str,
    ) -> bool {
        parameter_id(app, param_ref_id).is_some()
            && self.overridden.contains(&(
                self.instance_id(module).to_string(),
                param_ref_id.to_string(),
            ))
    }

    /// The vendor default of `param_ref_id` (app-relative) in the context of
    /// `module`, ignoring every override and `<Assign>`: the ref's `Value`,
    /// else the parameter's own `Value`, plus the instance's `BaseValue`
    /// argument where the parameter declares one (see [`DynamicConfig::value`]).
    pub fn vendor_default<S: DynamicSource + ?Sized>(
        &self,
        app: &S,
        module: Option<usize>,
        param_ref_id: &str,
    ) -> Option<String> {
        value_of(
            app,
            &HashMap::new(),
            self.instance_id(module),
            self.module_args(module),
            param_ref_id,
        )
    }

    /// Whether the value of `param_ref_id` in `module` was set by a reached
    /// `<Assign>` (and so is not the user's to choose).
    pub fn is_assigned(&self, module: Option<usize>, param_ref_id: &str) -> bool {
        let key = (
            self.instance_id(module).to_string(),
            param_ref_id.to_string(),
        );
        self.values.contains_key(&key) && !self.overridden.contains(&key)
    }

    /// The module instance id (e.g. `MD-15_M-26`) of `module`, `None` for the
    /// application itself.
    pub fn module_instance_id(&self, module: Option<usize>) -> Option<&str> {
        module
            .and_then(|i| self.modules.get(i))
            .map(|m| m.id.as_str())
    }

    /// The label a `TextParameterRefId` gives, read in the context of the
    /// module instance `module` the labelled element sits in (a module's own
    /// ref resolves in that instance, an application ref at the application
    /// level, as in the walk).
    ///
    /// The value is the effective one ([`DynamicConfig::value`]); for an
    /// enumeration parameter it is the matching enumeration text. Returns
    /// `None` when the ref is unknown or the value is empty after trimming.
    /// Feed the result to [`crate::label::substitute_label`].
    pub fn label<S: DynamicSource + ?Sized>(
        &self,
        app: &S,
        module: Option<usize>,
        text_parameter_ref: &str,
    ) -> Option<String> {
        let scope = scope_of(&self.modules, module, text_parameter_ref);
        let raw = self.value(app, scope, text_parameter_ref)?;
        let members = parameter_id(app, text_parameter_ref).and_then(|id| app.enum_members(id));
        let text = match members {
            Some(values) => raw
                .trim()
                .parse::<i64>()
                .ok()
                .and_then(|v| values.iter().find(|e| e.value == v))
                .map(|e| e.text.clone())
                .unwrap_or(raw),
            _ => raw,
        };
        let text = text.trim();
        (!text.is_empty()).then(|| text.to_string())
    }

    /// `text` with its `{{0}}`/`{{0:…}}` placeholder filled from
    /// `text_parameter_ref` in the context of `module` (see
    /// [`DynamicConfig::label`] and [`crate::label::substitute_label`]).
    /// Without a ref or a label the text is returned unchanged.
    pub fn labelled_text<S: DynamicSource + ?Sized>(
        &self,
        app: &S,
        module: Option<usize>,
        text: &str,
        text_parameter_ref: Option<&str>,
    ) -> String {
        let label = text_parameter_ref.and_then(|r| self.label(app, module, r));
        crate::label::substitute_label(text, label.as_deref())
    }

    /// The instance id used as the value key for `module`.
    fn instance_id(&self, module: Option<usize>) -> &str {
        module
            .and_then(|i| self.modules.get(i))
            .map(|m| m.id.as_str())
            .unwrap_or("")
    }
}

/// Evaluates `app`'s Dynamic section with the given parameter overrides.
///
/// `overrides` is keyed by app-relative `ParameterRef` id, optionally carrying
/// a project module-instance selector (`MD-<d>_M-<m>_MI-<n>_<param>_R-<r>`, the
/// device-file key form); a value applies to that ref, within that module
/// instance. A value is a ref's, not a parameter's, as in an ETS project
/// (`ParameterInstanceRef` is keyed by ref): when a configuration shows a
/// different ref of the same parameter, ETS writes that ref's own value (issue
/// #117: a Jung 3361-1MWW set to application type 1 shows other refs of its
/// send-delay parameters, and ETS writes their defaults, not the values set
/// through the refs of type 0). Keys that name no ref of this application are
/// listed in [`DynamicConfig::unresolved_overrides`].
///
/// `<Assign>` elements reached by the walk set their target to the source's
/// value (or the literal) and win over an override of the target, as in ETS
/// where an assigned parameter is not user-editable. The walk is repeated until
/// the assigned values settle.
///
/// Returns an empty configuration when the application has no Dynamic section.
pub fn evaluate_dynamic<S: DynamicSource + ?Sized>(
    app: &S,
    overrides: &BTreeMap<String, String>,
) -> DynamicConfig {
    let mut values: HashMap<(String, String), String> = HashMap::new();
    let mut overridden = HashSet::new();
    let mut unresolved = Vec::new();
    for (key, value) in overrides {
        let (instance, param_ref) = split_selector(key);
        match parameter_id(app, &param_ref) {
            Some(param_id) => {
                let value = enum_code_of(app, param_id, value);
                let k = (instance.unwrap_or_default(), param_ref);
                overridden.insert(k.clone());
                values.insert(k, value);
            }
            None => unresolved.push(key.clone()),
        }
    }

    let unions = UnionIndex::new(app);
    let placed = Rc::new(placed_parameters(app));
    let mut shared = SharedUnions::default();
    // The active parameters start empty and grow pass by pass (the least
    // fixpoint): a choose whose parameter is shown only later in document
    // order, or only through another gated choose, is taken once a pass has
    // reached that parameter.
    let mut active = HashSet::new();
    let mut walk = Walk::default();
    for _ in 0..MAX_ASSIGN_PASSES {
        walk = Walk {
            shared: std::mem::take(&mut shared),
            placed: Rc::clone(&placed),
            active_before: std::mem::take(&mut active),
            ..Walk::default()
        };
        walk.run(app, &values, app.dynamic(), None, 0);
        let next = unions.shared_memory(app, &values, &walk);
        let mut changed = next.images != walk.shared.images;
        shared = next;
        let now = walk.active_set(app);
        changed |= now != walk.active_before;
        active = now;
        for assign in &walk.assigns {
            let instance = walk.instance_id(assign.target_module).to_string();
            let new = match (&assign.value, &assign.source) {
                (Some(v), _) => Some(v.clone()),
                (None, Some(src)) => value_of(
                    app,
                    &values,
                    walk.instance_id(assign.source_module),
                    walk.module_args(assign.source_module),
                    src,
                ),
                (None, None) => None,
            };
            let Some(new) = new else {
                continue;
            };
            if parameter_id(app, &assign.target).is_none() {
                continue;
            }
            let key = (instance, assign.target.clone());
            if values.get(&key) != Some(&new) {
                overridden.remove(&key);
                values.insert(key, new);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // The written parameters: every reached ParameterRefRef plus the target
    // and source of every reached Assign, without duplicates.
    let ordinals = module_ordinals(app);
    for m in &mut walk.modules {
        m.ordinal = ordinals
            .get(&m.element_id)
            .map_or(0, |o| o.saturating_add(m.repetition.saturating_sub(1)));
    }
    let modules = walk.modules;
    let placement = |place: &Place, shown: bool| {
        let active = place.module.and_then(|i| modules.get(i));
        Placement {
            channel: place.ctx.channel.clone(),
            blocks: place.ctx.blocks.clone(),
            module: place.module,
            module_instance: active.map(|m| m.id.clone()),
            module_ordinal: active.map(|m| m.ordinal),
            shown,
        }
    };
    let mut seen = HashSet::new();
    let mut parameters = Vec::new();
    let mut parameter_placements = Vec::new();
    let assigned = walk.assigns.iter().flat_map(|a| {
        std::iter::once((
            ActiveParameter {
                module: a.target_module,
                param_ref_id: a.target.clone(),
            },
            &a.place,
        ))
        .chain(a.source.iter().map(|s| {
            (
                ActiveParameter {
                    module: a.source_module,
                    param_ref_id: s.clone(),
                },
                &a.place,
            )
        }))
    });
    let reached = walk
        .parameters
        .iter()
        .cloned()
        .zip(walk.parameter_places.iter())
        .map(|(p, place)| (p, place, true));
    for (p, place, shown) in reached.chain(assigned.map(|(p, place)| (p, place, false))) {
        if seen.insert(p.clone()) {
            parameters.push(p);
            parameter_placements.push(placement(place, shown));
        }
    }
    let mut seen = HashSet::new();
    let mut com_objects = Vec::new();
    let mut com_object_placements = Vec::new();
    for (c, place) in walk.com_objects.into_iter().zip(&walk.com_object_places) {
        if seen.insert(c.clone()) {
            com_objects.push(c);
            com_object_placements.push(placement(place, true));
        }
    }
    let mut seen = HashSet::new();
    let mut containers = Vec::new();
    for (container, place) in walk.containers {
        if seen.insert((place.module, container.id().to_string())) {
            containers.push(ActiveContainer {
                placement: placement(&place, true),
                container,
            });
        }
    }

    DynamicConfig {
        modules,
        parameters,
        com_objects,
        parameter_placements,
        com_object_placements,
        containers,
        unresolved_overrides: unresolved,
        values,
        overridden,
    }
}

/// The evaluations of one program's Dynamic section, memoized by the value
/// map they ran with (issue #367).
///
/// A parameter read-back evaluates the same program with the same values
/// several times: the read-back plan's image and group-object table, the
/// parameter decode, the group-object change and the octet attribution. On a
/// large program (ABB `M-0002_A-A0ED-10-9B4E`) each [`evaluate_dynamic`]
/// costs a fraction of a second, so the callers share one memo and each
/// distinct value map is evaluated once. The result is the one
/// [`evaluate_dynamic`] returns, so nothing a caller computes from it changes.
///
/// [`Self::evaluate_for`] answers from the memo only for the program the
/// memo was made for; any other program is evaluated directly.
pub struct DynamicMemo<'a, S: DynamicSource + ?Sized> {
    app: &'a S,
    entries: std::sync::Mutex<MemoEntries>,
}

/// The evaluations a [`DynamicMemo`] holds: each value map with its result.
type MemoEntries = Vec<(BTreeMap<String, String>, std::sync::Arc<DynamicConfig>)>;

impl<'a, S: DynamicSource + ?Sized> DynamicMemo<'a, S> {
    /// An empty memo for `app`.
    pub fn new(app: &'a S) -> DynamicMemo<'a, S> {
        DynamicMemo {
            app,
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// [`evaluate_dynamic`] of the memo's program with `values`, evaluated
    /// on the first request for this value map and shared after that.
    pub fn evaluate(&self, values: &BTreeMap<String, String>) -> std::sync::Arc<DynamicConfig> {
        if let Some((_, config)) = self.entries().iter().find(|(v, _)| v == values) {
            return std::sync::Arc::clone(config);
        }
        let config = std::sync::Arc::new(evaluate_dynamic(self.app, values));
        self.entries()
            .push((values.clone(), std::sync::Arc::clone(&config)));
        config
    }

    /// [`Self::evaluate`] when `app` is the memo's program (the same
    /// object), else a direct [`evaluate_dynamic`] of `app` that the memo
    /// does not keep.
    pub fn evaluate_for(
        &self,
        app: &S,
        values: &BTreeMap<String, String>,
    ) -> std::sync::Arc<DynamicConfig> {
        if std::ptr::addr_eq(app, self.app) {
            self.evaluate(values)
        } else {
            std::sync::Arc::new(evaluate_dynamic(app, values))
        }
    }

    /// How many distinct value maps the memo has evaluated.
    pub fn evaluations(&self) -> usize {
        self.entries().len()
    }

    /// The entries; a poisoned lock still holds whole entries.
    fn entries(&self) -> std::sync::MutexGuard<'_, MemoEntries> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Splits a device-file parameter key into its module instance key (see
/// [`ActiveModule::id`]) and the app-relative `ParameterRef` id:
/// `MD-15_M-26_MI-1_UP-22_R-27` becomes (`Some("MD-15_M-26")`,
/// `MD-15_UP-22_R-27`), `MD-1_M-1_MI-2_P-3_R-5` (`Some("MD-1_M-1_MI-2")`,
/// `MD-1_P-3_R-5`) and a submodule's `MD-1_M-1_MI-1_SM-1_M-1_MI-3_P-1_R-1`
/// (`Some("MD-1_M-1_MI-1_SM-1_M-1_MI-3")`, `MD-1_SM-1_P-1_R-1`). A key
/// without a selector is returned unchanged with `None`.
pub fn split_selector(key: &str) -> (Option<String>, String) {
    match parse_selector(key) {
        Some((instance, def, rest)) => (Some(instance), format!("{def}_{rest}")),
        None => (None, key.to_string()),
    }
}

/// Parses the module-instance selector at the start of `key`: the instance
/// key, the (innermost) module definition and what follows the selector.
fn parse_selector(key: &str) -> Option<(String, String, &str)> {
    /// The run of ASCII digits at the start of `s` and the rest.
    fn digits(s: &str) -> Option<(&str, &str)> {
        let end = s
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(s.len());
        (end > 0).then(|| s.split_at(end))
    }
    let (md, mut rest) = digits(key.strip_prefix("MD-")?)?;
    let mut def = format!("MD-{md}");
    let mut levels = 0usize;
    let mut last_mi: &str;
    loop {
        let (_, after) = digits(rest.strip_prefix("_M-")?)?;
        let (mi, after) = digits(after.strip_prefix("_MI-")?)?;
        levels += 1;
        last_mi = mi;
        rest = after;
        // A submodule instance follows: `_SM-<s>_M-<m>_MI-<n>`.
        if let Some(sm) = rest.strip_prefix("_SM-")
            && let Some((s, tail)) = digits(sm)
            && tail.starts_with("_M-")
        {
            def = format!("{def}_SM-{s}");
            rest = tail;
            continue;
        }
        break;
    }
    let param = rest.strip_prefix('_').filter(|p| !p.is_empty())?;
    let selector = &key[..key.len() - rest.len()];
    let instance = if levels == 1 && last_mi == "1" {
        selector
            .strip_suffix("_MI-1")
            .unwrap_or(selector)
            .to_string()
    } else {
        selector.to_string()
    };
    Some((instance, def, param))
}

/// The innermost module definition of an instance key (`MD-1_M-3` gives
/// `MD-1`, `MD-1_M-1_MI-1_SM-2_M-4_MI-1` gives `MD-1_SM-2`).
fn instance_module_def(instance: &str) -> String {
    let mut parts = instance.split('_');
    let mut def = parts.next().unwrap_or_default().to_string();
    for part in parts.filter(|p| p.starts_with("SM-")) {
        def.push('_');
        def.push_str(part);
    }
    def
}

/// The `Parameter` ids (full) the Dynamic section shows somewhere: every
/// parameter with a `<ParameterRefRef>` in the application's Dynamic section
/// or in any `<ModuleDef>`'s, in any branch. A `<choose>` on a parameter
/// outside this set is never gated by activity (see the module docs).
fn placed_parameters<S: DynamicSource + ?Sized>(app: &S) -> HashSet<String> {
    fn visit<S: DynamicSource + ?Sized>(app: &S, nodes: &[DynamicNode], out: &mut HashSet<String>) {
        for node in nodes {
            match node {
                DynamicNode::ParameterRefRef(r) => {
                    if let Some(id) = parameter_id(app, r) {
                        out.insert(id.to_string());
                    }
                }
                DynamicNode::Choose { whens, .. } => {
                    for w in whens {
                        visit(app, &w.children, out);
                    }
                }
                DynamicNode::Channel { children, .. }
                | DynamicNode::ParameterBlock { children, .. }
                | DynamicNode::Repeat { children, .. } => visit(app, children, out),
                DynamicNode::ComObjectRefRef(_)
                | DynamicNode::Module { .. }
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    let mut out = HashSet::new();
    visit(app, app.dynamic(), &mut out);
    for (_, body) in app.module_dynamics() {
        visit(app, body, &mut out);
    }
    out
}

/// The scope a ref reached inside `module` belongs to (see [`Walk::scope`]):
/// the innermost instance, `module` or one of its parents, whose module
/// definition the ref belongs to.
fn scope_of(modules: &[ActiveModule], module: Option<usize>, ref_id: &str) -> Option<usize> {
    let mut at = module;
    while let Some(i) = at {
        let m = modules.get(i)?;
        let own = ref_id
            .strip_prefix(m.module_def.as_str())
            .is_some_and(|rest| rest.starts_with('_'));
        if own {
            return Some(i);
        }
        at = m.parent;
    }
    if ref_id.starts_with("MD-") {
        module
    } else {
        None
    }
}

/// The device-file key of an app-relative id in a module instance: the id
/// itself at the application level (`instance` `None`), else the id with the
/// project module-instance selector inserted after its module definition
/// (`MD-1_M-3` and `MD-1_P-3_R-5` give `MD-1_M-3_MI-1_P-3_R-5`). This is the
/// key form device files use for parameters (and the inverse of
/// [`split_selector`]); it applies to parameter ids (`MD-1_P-3`), refs and
/// channel ids alike.
pub fn selector_key(instance: Option<&str>, app_relative_id: &str) -> String {
    let Some(instance) = instance else {
        return app_relative_id.to_string();
    };
    if instance.contains("_MI-") {
        // A key that carries its selector (a repetition or a submodule).
        let module_def = instance_module_def(instance);
        let rest = app_relative_id
            .strip_prefix(module_def.as_str())
            .and_then(|r| r.strip_prefix('_'))
            .unwrap_or(app_relative_id);
        return format!("{instance}_{rest}");
    }
    let module_def = instance.split_once("_M-").map_or(instance, |(md, _)| md);
    let rest = app_relative_id
        .strip_prefix(module_def)
        .and_then(|r| r.strip_prefix('_'))
        .unwrap_or(app_relative_id);
    format!("{instance}_MI-1_{rest}")
}

/// The one ref through which a parameter (one memory cell) is stored: see
/// [`visible_parameter_refs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleParameter {
    /// The parameter's key: its app-relative id with the module-instance
    /// selector (`P-12`, `MD-1_M-3_MI-1_P-3`; see [`selector_key`]).
    pub key: String,
    /// The app-relative `Parameter` id (`P-12`, `MD-1_P-3`).
    pub parameter_id: String,
    /// The scope of the parameter: index into [`DynamicConfig::modules`], as
    /// in [`ActiveParameter::module`].
    pub module: Option<usize>,
    /// The chosen app-relative `ParameterRef` id (`MD-1_P-3_R-5`).
    pub param_ref_id: String,
    /// The chosen ref in device-key form (`MD-1_M-3_MI-1_P-3_R-5`).
    pub ref_key: String,
    /// Index of the chosen ref in [`DynamicConfig::parameters`] (and
    /// [`DynamicConfig::parameter_placements`]).
    pub index: usize,
    /// The other active refs of the same parameter in the same scope,
    /// app-relative, in walk order.
    pub alternatives: Vec<String>,
}

/// Picks one active `ParameterRef` per parameter (per module instance), so a
/// parameter is stored once per memory cell.
///
/// The rule: among the entries of [`DynamicConfig::parameters`] that point at
/// the same `Parameter` in the same scope, take the first one that is shown
/// (reached through a `<ParameterRefRef>`, [`Placement::shown`]) in walk
/// order, which is document order with each reached module body expanded in
/// place; when none is shown (the parameter is only touched by an
/// `<Assign>`), take the first entry. Every other active ref of that
/// parameter is listed in [`VisibleParameter::alternatives`]. Refs that
/// resolve to no parameter are skipped. The result is ordered by the chosen
/// entry's index.
pub fn visible_parameter_refs<S: DynamicSource + ?Sized>(
    app: &S,
    config: &DynamicConfig,
) -> Vec<VisibleParameter> {
    let prefix = format!("{}_", app.program_id());
    // (instance, parameter id) -> indices into config.parameters, walk order.
    type Key = (Option<usize>, String);
    let mut groups: Vec<(Key, Vec<usize>)> = Vec::new();
    let mut slot: HashMap<Key, usize> = HashMap::new();
    for (i, p) in config.parameters.iter().enumerate() {
        let Some(pid) = parameter_id(app, &p.param_ref_id) else {
            continue;
        };
        let rel = pid.strip_prefix(&prefix).unwrap_or(pid).to_string();
        let key = (p.module, rel);
        match slot.get(&key) {
            Some(&g) => groups[g].1.push(i),
            None => {
                slot.insert(key.clone(), groups.len());
                groups.push((key, vec![i]));
            }
        }
    }
    let shown = |i: usize| config.parameter_placements.get(i).is_some_and(|p| p.shown);
    let mut out: Vec<VisibleParameter> = groups
        .into_iter()
        .filter_map(|((module, parameter_id), indices)| {
            let chosen = indices
                .iter()
                .copied()
                .find(|&i| shown(i))
                .or_else(|| indices.first().copied())?;
            let param_ref_id = config.parameters.get(chosen)?.param_ref_id.clone();
            let mut alternatives: Vec<String> = Vec::new();
            for &i in &indices {
                let r = &config.parameters[i].param_ref_id;
                if *r != param_ref_id && !alternatives.contains(r) {
                    alternatives.push(r.clone());
                }
            }
            let instance = config.module_instance_id(module);
            Some(VisibleParameter {
                key: selector_key(instance, &parameter_id),
                ref_key: selector_key(instance, &param_ref_id),
                parameter_id,
                module,
                param_ref_id,
                index: chosen,
                alternatives,
            })
        })
        .collect();
    out.sort_by_key(|v| v.index);
    out
}

/// The 1-based ordinal of every module instance id among the instances of
/// its module definition, in `M-<m>` order (numeric `m`), counted over every
/// `<Module>` in the application's and the module definitions' Dynamic
/// sections, in any branch.
fn module_ordinals<S: DynamicSource + ?Sized>(app: &S) -> HashMap<String, u32> {
    fn visit(nodes: &[DynamicNode], out: &mut BTreeMap<String, Vec<String>>) {
        for node in nodes {
            match node {
                DynamicNode::Module { id, module_def, .. } => {
                    out.entry(module_def.clone()).or_default().push(id.clone());
                }
                DynamicNode::Choose { whens, .. } => {
                    for w in whens {
                        visit(&w.children, out);
                    }
                }
                DynamicNode::Channel { children, .. }
                | DynamicNode::ParameterBlock { children, .. }
                | DynamicNode::Repeat { children, .. } => visit(children, out),
                DynamicNode::ParameterRefRef(_)
                | DynamicNode::ComObjectRefRef(_)
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    let mut by_def = BTreeMap::new();
    visit(app.dynamic(), &mut by_def);
    for (_, body) in app.module_dynamics() {
        visit(body, &mut by_def);
    }
    let m_number = |id: &str| -> Option<u64> { id.rsplit_once("_M-")?.1.parse().ok() };
    let mut out = HashMap::new();
    for mut ids in by_def.into_values() {
        ids.sort_by(|a, b| m_number(a).cmp(&m_number(b)).then_with(|| a.cmp(b)));
        ids.dedup();
        for (i, id) in ids.into_iter().enumerate() {
            out.insert(id, u32::try_from(i + 1).unwrap_or(u32::MAX));
        }
    }
    out
}

/// The full `Parameter` id an app-relative `ParameterRef` id points at.
fn parameter_id<'a, S: DynamicSource + ?Sized>(app: &'a S, param_ref_id: &str) -> Option<&'a str> {
    app.parameter_ref(param_ref_id).map(|(id, _)| id)
}

/// An override value as the evaluation compares it: an enumeration member
/// named by its label (as `bussard import` writes it, in the lock's language)
/// becomes its code, so a `<when test>` on the parameter selects the branch
/// the member stands for (issue #231). Any other value, and a label no member
/// uniquely carries (the image builder refuses it with the list of labels),
/// is kept as written.
fn enum_code_of<S: DynamicSource + ?Sized>(app: &S, param_id: &str, value: &str) -> String {
    if value.trim().parse::<i64>().is_ok() {
        return value.to_string();
    }
    match app.enum_members(param_id) {
        Some(values) => match enum_member_by_label(values, value) {
            LabelMatch::Member(code) => code.to_string(),
            LabelMatch::Ambiguous | LabelMatch::Unknown => value.to_string(),
        },
        _ => value.to_string(),
    }
}

/// The effective value of an app-relative `ParameterRef` in one instance: an
/// override or `<Assign>` result, else the ref's `Value`, else the parameter's
/// `Value`. A default of a parameter with a `BaseValue` argument has that
/// argument's value in the instance (`args`) added to it, as ETS does (issue
/// #126: the Jung 230021SU input module's "internal group communication"
/// parameter is `Value="0" BaseValue="MD-1_A-19"`, 4 in one instance and 5 in
/// another, and its `<choose>` selects the instance's App-ID and debounce refs).
fn value_of<S: DynamicSource + ?Sized>(
    app: &S,
    values: &HashMap<(String, String), String>,
    instance: &str,
    args: Option<&HashMap<String, i64>>,
    param_ref_id: &str,
) -> Option<String> {
    let (param_id, ref_value) = app.parameter_ref(param_ref_id)?;
    if let Some(v) = values.get(&(instance.to_string(), param_ref_id.to_string())) {
        return Some(v.clone());
    }
    let param = app.parameter(param_id);
    let default = ref_value
        .map(str::to_string)
        .or_else(|| param.and_then(|(default, _)| default).map(str::to_string));
    let base = param
        .and_then(|(_, base_value)| base_value)
        .map(|arg| {
            arg.strip_prefix(&format!("{}_", app.program_id()))
                .unwrap_or(arg)
        })
        .and_then(|arg| args?.get(arg).copied());
    match base {
        Some(base) => {
            let own = match default.as_deref().map(str::trim) {
                None | Some("") => 0,
                Some(v) => match v.parse::<i64>() {
                    Ok(n) => n,
                    // A non-integer default takes no base.
                    Err(_) => return default,
                },
            };
            Some(own.saturating_add(base).to_string())
        }
        None => default,
    }
}

/// The `<when>` branches of a `<choose>` the walk takes when the controlling
/// parameter has `value`, as indices into `tests` (the branches' tests in
/// document order): every branch whose test matches, or, when none does,
/// every `<when default="true">` branch. `value` is the parameter's value as
/// a number, `None` when it has none or it does not parse as one; it then
/// matches no test, so the default branches are taken. A
/// [`WhenTest::Unknown`] test never matches. Whether the controlling
/// parameter is active (issue #159) is the caller's to check.
///
/// This is the one definition of `<choose>` semantics: the Dynamic walk and
/// the `<choose>` blocks of a load procedure (issue #402) both decide their
/// branches with it.
pub fn taken_branches<'a, I>(tests: I, value: Option<f64>) -> Vec<usize>
where
    I: IntoIterator<Item = &'a WhenTest>,
    I::IntoIter: Clone,
{
    let tests = tests.into_iter();
    let hits: Vec<usize> = tests
        .clone()
        .enumerate()
        .filter(|(_, t)| when_matches(t, value))
        .map(|(i, _)| i)
        .collect();
    if !hits.is_empty() {
        return hits;
    }
    tests
        .enumerate()
        .filter(|(_, t)| **t == WhenTest::Default)
        .map(|(i, _)| i)
        .collect()
}

/// Whether a `<when>` test (other than `default`) matches a value.
fn when_matches(test: &WhenTest, value: Option<f64>) -> bool {
    let Some(v) = value else { return false };
    match test {
        // Exact values compare as integers; a fractional value matches none.
        WhenTest::Values(vs) => v.fract() == 0.0 && vs.iter().any(|&x| x as f64 == v),
        WhenTest::Compare { op, value } => {
            let x = *value as f64;
            match op {
                CompareOp::Ne => v != x,
                CompareOp::Lt => v < x,
                CompareOp::Le => v <= x,
                CompareOp::Gt => v > x,
                CompareOp::Ge => v >= x,
            }
        }
        WhenTest::Default | WhenTest::Unknown(_) => false,
    }
}

/// A reached `<Assign>`.
#[derive(Debug, Clone)]
struct ReachedAssign {
    /// The scope of `target` (see [`Walk::scope`]).
    target_module: Option<usize>,
    target: String,
    /// The scope of `source`.
    source_module: Option<usize>,
    source: Option<String>,
    value: Option<String>,
    /// Where the `<Assign>` element sits.
    place: Place,
}

/// One pass over the Dynamic tree.
#[derive(Debug, Default)]
struct Walk {
    modules: Vec<ActiveModule>,
    parameters: Vec<ActiveParameter>,
    com_objects: Vec<ActiveComObject>,
    /// Where each entry of `parameters` was reached, same index.
    parameter_places: Vec<Place>,
    /// Where each entry of `com_objects` was reached, same index.
    com_object_places: Vec<Place>,
    /// Every container entered, with the place it sits in (outside it).
    containers: Vec<(Container, Place)>,
    /// The channel and block path at the current point of the walk.
    ctx: Rc<Context>,
    assigns: Vec<ReachedAssign>,
    /// What the previous pass left in the unions' shared memory.
    shared: SharedUnions,
    /// The parameters the Dynamic section shows somewhere
    /// ([`placed_parameters`]).
    placed: Rc<HashSet<String>>,
    /// The active parameters the previous pass reached, keyed by (module
    /// instance id or `""`, full `Parameter` id).
    active_before: HashSet<(String, String)>,
    /// The parameters this pass has reached so far, same keys.
    active_now: HashSet<(String, String)>,
    /// The current value of every allocator this pass drew from, keyed by
    /// the instance owning it (`None` for an application allocator, the
    /// instance of the declaring `<ModuleDef>` for a module one) and the
    /// app-relative allocator id (issue #449).
    allocators: HashMap<(Option<usize>, String), i64>,
    /// The repetition of the innermost `<Repeat>` around the current point
    /// of the walk (within the current module body), 1 outside any.
    repetition: u32,
}

/// The most repetitions one `<Repeat>` is expanded to: a guard against a
/// malformed count, far above what products declare (64 DALI channels).
const MAX_REPEAT: i64 = 4096;

/// The shared memory of every union a pass reached a member of, and the values
/// the members it did not reach read from it.
///
/// Union members overlay one memory region, so in ETS a member that is not
/// shown has whatever value the shown member left in those bits, not its own
/// default. A `<choose>` on such a member branches on that value (the ABB
/// BE/S16's template channel: `Par_Operation_11` defaults to 3, but its union
/// sibling `Par_Operation_2` is the one shown, with 2, so the `when test="3"`
/// block with `Par_Operation_5` is not shown and ETS writes `Par_Operation_4`).
#[derive(Debug, Default)]
struct SharedUnions {
    /// Keyed by (module instance id or `""`, union index): the region's bits.
    images: BTreeMap<(String, usize), Vec<u8>>,
    /// Keyed by (module instance id or `""`, app-relative `ParameterRef` id):
    /// the value an unreached member reads.
    values: HashMap<(String, String), String>,
}

/// Where each union member parameter sits: parameter id to (union index,
/// member bit position relative to the union, member width in bits, signed).
struct UnionIndex {
    members: HashMap<String, (usize, u32, u32, bool)>,
    /// Every app-relative `ParameterRef` of a member parameter, with its
    /// member's entry of `members`.
    member_refs: Vec<(String, (usize, u32, u32, bool))>,
}

impl UnionIndex {
    fn new<S: DynamicSource + ?Sized>(app: &S) -> Self {
        let mut members = HashMap::new();
        for (ui, union) in app.unions().iter().enumerate() {
            for member in &union.members {
                let Some((bits, signed)) = app.integer_width(&member.parameter) else {
                    continue;
                };
                let pos =
                    member.offset.unwrap_or(0) * 8 + u32::from(member.bit_offset.unwrap_or(0));
                members.insert(member.parameter.clone(), (ui, pos, bits, signed));
            }
        }
        let member_refs = if members.is_empty() {
            Vec::new()
        } else {
            app.parameter_refs()
                .filter_map(|(rel, param)| Some((rel.to_string(), *members.get(param)?)))
                .collect()
        };
        Self {
            members,
            member_refs,
        }
    }

    /// Lays the reached members' values into their unions' memory, then reads
    /// every other ref of a member of those unions back out of it.
    fn shared_memory<S: DynamicSource + ?Sized>(
        &self,
        app: &S,
        values: &HashMap<(String, String), String>,
        walk: &Walk,
    ) -> SharedUnions {
        let mut out = SharedUnions::default();
        if self.members.is_empty() {
            return out;
        }
        let mut reached: HashSet<(String, String)> = HashSet::new();
        for p in &walk.parameters {
            let instance = walk.instance_id(p.module).to_string();
            reached.insert((instance.clone(), p.param_ref_id.clone()));
            let Some(&(ui, pos, bits, _)) =
                parameter_id(app, &p.param_ref_id).and_then(|id| self.members.get(id))
            else {
                continue;
            };
            let Some(v) = value_of(
                app,
                values,
                &instance,
                walk.module_args(p.module),
                &p.param_ref_id,
            )
            .and_then(|v| v.trim().parse::<i64>().ok()) else {
                continue;
            };
            let size = app.unions()[ui].size_bits.unwrap_or(0).max(pos + bits);
            let image = out
                .images
                .entry((instance, ui))
                .or_insert_with(|| vec![0; size.div_ceil(8) as usize]);
            put_bits(image, pos, bits, v as u64);
        }
        let mut by_union: HashMap<usize, Vec<(&String, &Vec<u8>)>> = HashMap::new();
        for ((instance, ui), image) in &out.images {
            by_union.entry(*ui).or_default().push((instance, image));
        }
        let mut read = HashMap::new();
        for (rel, (ui, pos, bits, signed)) in &self.member_refs {
            let (ui, pos, bits, signed) = (*ui, *pos, *bits, *signed);
            let Some(images) = by_union.get(&ui) else {
                continue;
            };
            for (instance, image) in images {
                let key = ((*instance).clone(), rel.to_string());
                if reached.contains(&key) {
                    continue;
                }
                let raw = get_bits(image, pos, bits);
                let v = if signed && bits > 0 && bits < 64 && raw >> (bits - 1) & 1 == 1 {
                    (raw as i64) - (1i64 << bits)
                } else {
                    raw as i64
                };
                read.insert(key, v.to_string());
            }
        }
        out.values = read;
        out
    }
}

/// Writes the low `bits` of `value` MSB-first at bit `pos` of `image`.
fn put_bits(image: &mut [u8], pos: u32, bits: u32, value: u64) {
    for i in 0..bits {
        let bit = (value >> (bits - 1 - i)) & 1;
        let at = (pos + i) as usize;
        let Some(byte) = image.get_mut(at / 8) else {
            return;
        };
        let mask = 0x80u8 >> (at % 8);
        if bit == 1 {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
}

/// Reads `bits` MSB-first from bit `pos` of `image` (missing bits read 0).
fn get_bits(image: &[u8], pos: u32, bits: u32) -> u64 {
    (0..bits).fold(0u64, |acc, i| {
        let at = (pos + i) as usize;
        let bit = image.get(at / 8).map_or(0, |b| (b >> (7 - at % 8)) & 1);
        (acc << 1) | u64::from(bit)
    })
}

impl Walk {
    /// The active parameters this pass reached: every reached
    /// `<ParameterRefRef>` and every reached `<Assign>` target.
    fn active_set<S: DynamicSource + ?Sized>(&self, app: &S) -> HashSet<(String, String)> {
        let mut out = self.active_now.clone();
        for a in &self.assigns {
            if let Some(id) = parameter_id(app, &a.target) {
                out.insert((
                    self.instance_id(a.target_module).to_string(),
                    id.to_string(),
                ));
            }
        }
        out
    }

    /// Whether the parameter of `param_ref_id` in `instance` is active, so a
    /// `<choose>` on it may select a branch (issue #159, see the module docs).
    fn is_active<S: DynamicSource + ?Sized>(
        &self,
        app: &S,
        instance: &str,
        param_ref_id: &str,
    ) -> bool {
        let Some(id) = parameter_id(app, param_ref_id) else {
            return true;
        };
        if !self.placed.contains(id) {
            return true;
        }
        let key = (instance.to_string(), id.to_string());
        self.active_now.contains(&key) || self.active_before.contains(&key)
    }

    fn module_args(&self, module: Option<usize>) -> Option<&HashMap<String, i64>> {
        module.and_then(|i| self.modules.get(i)).map(|m| &m.args)
    }

    /// The key of a new instance of the `<Module>` element `element` of
    /// `module_def`, reached inside `parent` in repetition `repetition` (see
    /// [`ActiveModule::id`]).
    fn instance_key(
        &self,
        parent: Option<usize>,
        element: &str,
        module_def: &str,
        repetition: u32,
    ) -> String {
        let parent = parent.and_then(|i| self.modules.get(i));
        match parent {
            Some(p) if module_def.contains("_SM-") => {
                let outer = p.selector();
                let md = outer.split('_').next().unwrap_or_default();
                let own = element
                    .strip_prefix(md)
                    .and_then(|r| r.strip_prefix('_'))
                    .unwrap_or(element);
                format!("{outer}_{own}_MI-{repetition}")
            }
            _ if repetition > 1 => format!("{element}_MI-{repetition}"),
            _ => element.to_string(),
        }
    }

    /// The value of a computed `<NumericArg>` for a new instance reached
    /// inside `parent`: the allocator's current value (which then advances
    /// by the argument's `Allocates`) or the literal, plus the parent's value
    /// of the `BaseValue` argument. `None` when an input is missing: an
    /// unknown allocator, an allocator past its `maxInclusive`, or a
    /// `BaseValue` the parent has no value for.
    fn computed_arg<S: DynamicSource + ?Sized>(
        &mut self,
        app: &S,
        parent: Option<usize>,
        arg: &ComputedArg,
    ) -> Option<i64> {
        let base = match &arg.base {
            Some(b) => *self.module_args(parent)?.get(b)?,
            None => 0,
        };
        let own = match &arg.allocator {
            None => arg.value.unwrap_or(0),
            Some(alloc) => {
                // A module definition's allocator counts per instance of it.
                let owner = match alloc.rsplit_once("_L-") {
                    Some((def, _)) if def.starts_with("MD-") => {
                        let mut at = parent;
                        loop {
                            let m = self.modules.get(at?)?;
                            if m.module_def == def {
                                break at;
                            }
                            at = m.parent;
                        }
                    }
                    _ => None,
                };
                let decl = app.allocator(alloc)?;
                let allocates = app.argument_allocates(&arg.arg).unwrap_or(0);
                let current = self
                    .allocators
                    .entry((owner, alloc.clone()))
                    .or_insert(decl.start);
                let value = *current;
                if let Some(max) = decl.max_inclusive
                    && value.saturating_add(allocates.max(1)).saturating_sub(1) > max
                {
                    return None;
                }
                *current = value.saturating_add(allocates);
                value
            }
        };
        Some(own.saturating_add(base))
    }

    fn instance_id(&self, module: Option<usize>) -> &str {
        module
            .and_then(|i| self.modules.get(i))
            .map(|m| m.id.as_str())
            .unwrap_or("")
    }

    /// The current location, inside the module instance `module`.
    fn place(&self, module: Option<usize>) -> Place {
        Place {
            ctx: Rc::clone(&self.ctx),
            module,
        }
    }

    /// The scope a ref reached inside `module` belongs to: the module instance
    /// for a ref of its own `ModuleDef` (`MD-3_P-3_R-3` inside an `MD-3`
    /// instance), the application for an application ref (`P-15_R-16`).
    ///
    /// A module's Dynamic body may test and assign application parameters:
    /// the Jung 230021SU blind module chooses on the application's "safety
    /// release" `P-15_R-16` and assigns the application's alarm parameters to
    /// its own. Those resolve to the application's values, never to a
    /// per-instance copy (issue #126).
    fn scope(&self, module: Option<usize>, ref_id: &str) -> Option<usize> {
        scope_of(&self.modules, module, ref_id)
    }

    fn run<S: DynamicSource + ?Sized>(
        &mut self,
        app: &S,
        values: &HashMap<(String, String), String>,
        nodes: &[DynamicNode],
        module: Option<usize>,
        depth: usize,
    ) {
        for node in nodes {
            match node {
                DynamicNode::ParameterRefRef(r) => {
                    let scope = self.scope(module, r);
                    if let Some(id) = parameter_id(app, r) {
                        self.active_now
                            .insert((self.instance_id(scope).to_string(), id.to_string()));
                    }
                    self.parameters.push(ActiveParameter {
                        module: scope,
                        param_ref_id: r.clone(),
                    });
                    self.parameter_places.push(self.place(module));
                }
                DynamicNode::ComObjectRefRef(r) => {
                    self.com_objects.push(ActiveComObject {
                        module: self.scope(module, r),
                        com_object_ref_id: r.clone(),
                    });
                    self.com_object_places.push(self.place(module));
                }
                DynamicNode::Channel { children, .. } => {
                    let channel = node.channel_ref();
                    if let Some(c) = &channel {
                        self.containers
                            .push((Container::Channel(c.clone()), self.place(module)));
                    }
                    let outer = Rc::clone(&self.ctx);
                    self.ctx = Rc::new(Context {
                        channel,
                        blocks: outer.blocks.clone(),
                    });
                    self.run(app, values, children, module, depth);
                    self.ctx = outer;
                }
                DynamicNode::ParameterBlock { children, .. } => {
                    let block = node.block_ref();
                    if let Some(b) = &block {
                        self.containers
                            .push((Container::Block(b.clone()), self.place(module)));
                    }
                    let outer = Rc::clone(&self.ctx);
                    let mut blocks = outer.blocks.clone();
                    blocks.extend(block);
                    self.ctx = Rc::new(Context {
                        channel: outer.channel.clone(),
                        blocks,
                    });
                    self.run(app, values, children, module, depth);
                    self.ctx = outer;
                }
                DynamicNode::Choose {
                    param_ref_id,
                    whens,
                } => {
                    let scope = self.scope(module, param_ref_id);
                    let instance = self.instance_id(scope);
                    let key = (instance.to_string(), param_ref_id.clone());
                    let shared = (!values.contains_key(&key))
                        .then(|| self.shared.values.get(&key).cloned())
                        .flatten();
                    // An inactive controlling parameter selects no branch, not
                    // even the default one; a union member reading live shared
                    // memory is active.
                    if shared.is_none() && !self.is_active(app, instance, param_ref_id) {
                        continue;
                    }
                    let value = shared
                        .or_else(|| {
                            value_of(app, values, instance, self.module_args(scope), param_ref_id)
                        })
                        .and_then(|v| v.trim().parse::<f64>().ok());
                    for i in taken_branches(whens.iter().map(|w| &w.test), value) {
                        if let Some(w) = whens.get(i) {
                            self.run(app, values, &w.children, module, depth);
                        }
                    }
                }
                DynamicNode::Module {
                    id,
                    module_def,
                    args,
                    computed_args,
                } => {
                    if depth >= MAX_MODULE_DEPTH {
                        continue;
                    }
                    let Some(body) = app.module_dynamic(module_def) else {
                        continue;
                    };
                    let mut resolved = args.clone();
                    for arg in computed_args {
                        if let Some(v) = self.computed_arg(app, module, arg) {
                            resolved.insert(arg.arg.clone(), v);
                        }
                    }
                    let idx = self.modules.len();
                    // `Walk::default()` starts at 0: outside any `<Repeat>`.
                    let repetition = self.repetition.max(1);
                    self.modules.push(ActiveModule {
                        id: self.instance_key(module, id, module_def, repetition),
                        element_id: id.clone(),
                        module_def: module_def.clone(),
                        args: resolved,
                        parent: module,
                        repetition,
                        ordinal: 0,
                    });
                    let outer = std::mem::replace(&mut self.repetition, 1);
                    self.run(app, values, body, Some(idx), depth + 1);
                    self.repetition = outer;
                }
                DynamicNode::Repeat {
                    param_ref_id,
                    count,
                    children,
                    ..
                } => {
                    let n = match param_ref_id {
                        Some(r) => {
                            let scope = self.scope(module, r);
                            value_of(
                                app,
                                values,
                                self.instance_id(scope),
                                self.module_args(scope),
                                r,
                            )
                            .and_then(|v| v.trim().parse::<i64>().ok())
                            .unwrap_or(0)
                        }
                        None => count.map_or(0, i64::from),
                    };
                    let outer = self.repetition;
                    for k in 1..=n.clamp(0, MAX_REPEAT) {
                        self.repetition = u32::try_from(k).unwrap_or(u32::MAX);
                        self.run(app, values, children, module, depth);
                    }
                    self.repetition = outer;
                }
                DynamicNode::Assign {
                    target,
                    source,
                    value,
                } => self.assigns.push(ReachedAssign {
                    target_module: self.scope(module, target),
                    target: target.clone(),
                    source_module: source.as_deref().and_then(|s| self.scope(module, s)),
                    source: source.clone(),
                    value: value.clone(),
                    place: self.place(module),
                }),
            }
        }
    }
}

/// A `<Channel>` or `<ParameterBlock>` of the Dynamic section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Container {
    /// A `<Channel>`.
    Channel(ChannelRef),
    /// A `<ParameterBlock>`.
    Block(BlockRef),
}

impl Container {
    /// The container's app-relative id (`CH-2`, `PB-13`, `MD-1_PB-2`).
    pub fn id(&self) -> &str {
        match self {
            Container::Channel(c) => &c.id,
            Container::Block(b) => &b.id,
        }
    }
}

/// A container the walk entered (see [`DynamicConfig::containers`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveContainer {
    /// The channel or block.
    pub container: Container,
    /// Where it sits: the enclosing channel and blocks (not itself) and the
    /// module instance whose body contains it. [`Placement::shown`] is always
    /// `true`.
    pub placement: Placement,
}

/// One `<when>` a ref or object sits behind (see [`RefOccurrence::gates`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefGate {
    /// The `<choose>`'s controlling `ParameterRef` id, as written.
    pub param_ref_id: String,
    /// The branch's test.
    pub test: WhenTest,
    /// The tests of the other branches of the same `<choose>`, in document
    /// order: a [`WhenTest::Default`] branch is taken when none of them
    /// matches.
    pub siblings: Vec<WhenTest>,
}

impl RefGate {
    /// Whether the walk takes this branch when the controlling parameter has
    /// `value` (a number, or `None` when it has none): the test matches, or,
    /// for a [`WhenTest::Default`] branch, no sibling matches. Whether the
    /// controlling parameter is active (issue #159) is the caller's to check.
    pub fn holds(&self, value: Option<f64>) -> bool {
        if self.test == WhenTest::Default {
            return !self.siblings.iter().any(|t| when_matches(t, value));
        }
        when_matches(&self.test, value)
    }
}

/// One place a `<ParameterRefRef>` or `<ComObjectRefRef>` occurs in the
/// Dynamic section, independent of any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefOccurrence {
    /// The module definition whose body holds it (`MD-1`), `None` in the
    /// application's own Dynamic section. Module instances are not expanded.
    pub module_def: Option<String>,
    /// The enclosing `<Channel>`, if any.
    pub channel: Option<ChannelRef>,
    /// The enclosing `<ParameterBlock>`s, outermost first.
    pub blocks: Vec<BlockRef>,
    /// The `<when>` branches in front of it, outermost first.
    pub gates: Vec<RefGate>,
    /// How many of [`Self::gates`] stand in front of its innermost
    /// container (the last of [`Self::blocks`], else [`Self::channel`]):
    /// `gates[container_gates..]` are the conditions inside that container,
    /// between the container and the ref.
    pub container_gates: usize,
}

/// Every occurrence of every parameter ref and com-object ref in the Dynamic
/// section and the module definitions' Dynamic sections: one value-free pass,
/// every branch taken. The application's section comes first, then the
/// module definitions by id; within one section, document order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefIndex {
    parameters: BTreeMap<String, Vec<RefOccurrence>>,
    com_objects: BTreeMap<String, Vec<RefOccurrence>>,
}

impl RefIndex {
    /// Indexes `src`'s Dynamic sections.
    pub fn new<S: DynamicSource + ?Sized>(src: &S) -> Self {
        let mut index = RefIndex::default();
        let mut walker = IndexWalk {
            module_def: None,
            channel: None,
            blocks: Vec::new(),
            gates: Vec::new(),
            container_gates: 0,
            index: &mut index,
        };
        walker.visit(src.dynamic());
        let mut defs: Vec<(&str, &[DynamicNode])> = src.module_dynamics().collect();
        defs.sort_by(|a, b| a.0.cmp(b.0));
        for (def, body) in defs {
            walker.module_def = Some(def.to_string());
            walker.visit(body);
        }
        index
    }

    /// Every occurrence of the app-relative `ParameterRef` id `ref_id`.
    pub fn parameter(&self, ref_id: &str) -> &[RefOccurrence] {
        self.parameters.get(ref_id).map_or(&[], Vec::as_slice)
    }

    /// Every occurrence of the app-relative `ComObjectRef` id `ref_id`.
    pub fn com_object(&self, ref_id: &str) -> &[RefOccurrence] {
        self.com_objects.get(ref_id).map_or(&[], Vec::as_slice)
    }

    /// Every indexed parameter ref with its occurrences, by ref id.
    pub fn parameters(&self) -> impl Iterator<Item = (&str, &[RefOccurrence])> {
        self.parameters
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// Every indexed com-object ref with its occurrences, by ref id.
    pub fn com_objects(&self) -> impl Iterator<Item = (&str, &[RefOccurrence])> {
        self.com_objects
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
    }
}

/// The state of the [`RefIndex`] pass.
struct IndexWalk<'a> {
    module_def: Option<String>,
    channel: Option<ChannelRef>,
    blocks: Vec<BlockRef>,
    gates: Vec<RefGate>,
    /// `gates.len()` when the innermost container began.
    container_gates: usize,
    index: &'a mut RefIndex,
}

impl IndexWalk<'_> {
    fn occurrence(&self) -> RefOccurrence {
        RefOccurrence {
            module_def: self.module_def.clone(),
            channel: self.channel.clone(),
            blocks: self.blocks.clone(),
            gates: self.gates.clone(),
            container_gates: self.container_gates,
        }
    }

    fn visit(&mut self, nodes: &[DynamicNode]) {
        for node in nodes {
            match node {
                DynamicNode::ParameterRefRef(r) => {
                    let occ = self.occurrence();
                    self.index
                        .parameters
                        .entry(r.clone())
                        .or_default()
                        .push(occ);
                }
                DynamicNode::ComObjectRefRef(r) => {
                    let occ = self.occurrence();
                    self.index
                        .com_objects
                        .entry(r.clone())
                        .or_default()
                        .push(occ);
                }
                DynamicNode::Channel { children, .. } => {
                    let outer = std::mem::replace(&mut self.channel, node.channel_ref());
                    let gates = std::mem::replace(&mut self.container_gates, self.gates.len());
                    self.visit(children);
                    self.channel = outer;
                    self.container_gates = gates;
                }
                DynamicNode::ParameterBlock { children, .. } => {
                    let depth = self.blocks.len();
                    self.blocks.extend(node.block_ref());
                    let gates = std::mem::replace(&mut self.container_gates, self.gates.len());
                    self.visit(children);
                    self.blocks.truncate(depth);
                    self.container_gates = gates;
                }
                DynamicNode::Choose {
                    param_ref_id,
                    whens,
                } => {
                    for (i, w) in whens.iter().enumerate() {
                        let siblings = whens
                            .iter()
                            .enumerate()
                            .filter(|&(j, _)| j != i)
                            .map(|(_, o)| o.test.clone())
                            .collect();
                        self.gates.push(RefGate {
                            param_ref_id: param_ref_id.clone(),
                            test: w.test.clone(),
                            siblings,
                        });
                        self.visit(&w.children);
                        self.gates.pop();
                    }
                }
                DynamicNode::Repeat { children, .. } => self.visit(children),
                DynamicNode::Module { .. } | DynamicNode::Assign { .. } => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built source: the evaluator needs no XML.
    #[derive(Default)]
    struct TestSource {
        dynamic: Vec<DynamicNode>,
        module_dynamics: HashMap<String, Vec<DynamicNode>>,
        /// ref id -> (parameter id, ref value)
        refs: HashMap<String, (String, Option<String>)>,
        /// parameter id -> default
        params: HashMap<String, Option<String>>,
    }

    impl DynamicSource for TestSource {
        fn program_id(&self) -> &str {
            "A"
        }
        fn dynamic(&self) -> &[DynamicNode] {
            &self.dynamic
        }
        fn module_dynamic(&self, module_def: &str) -> Option<&[DynamicNode]> {
            self.module_dynamics.get(module_def).map(Vec::as_slice)
        }
        fn module_dynamics(&self) -> Box<dyn Iterator<Item = (&str, &[DynamicNode])> + '_> {
            Box::new(
                self.module_dynamics
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_slice())),
            )
        }
        fn parameter_ref(&self, ref_id: &str) -> Option<(&str, Option<&str>)> {
            self.refs
                .get(ref_id)
                .map(|(p, v)| (p.as_str(), v.as_deref()))
        }
        fn parameter_refs(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
            Box::new(self.refs.iter().map(|(r, (p, _))| (r.as_str(), p.as_str())))
        }
        fn parameter(&self, param_id: &str) -> Option<(Option<&str>, Option<&str>)> {
            self.params.get(param_id).map(|d| (d.as_deref(), None))
        }
        fn integer_width(&self, _param_id: &str) -> Option<(u32, bool)> {
            None
        }
        fn enum_members(&self, _param_id: &str) -> Option<&[EnumValue]> {
            None
        }
        fn unions(&self) -> &[Union] {
            &[]
        }
    }

    fn block(id: &str, children: Vec<DynamicNode>) -> DynamicNode {
        DynamicNode::ParameterBlock {
            id: id.to_string(),
            name: None,
            text: None,
            text_parameter_ref: None,
            param_ref: None,
            children,
        }
    }

    fn channel(id: &str, children: Vec<DynamicNode>) -> DynamicNode {
        DynamicNode::Channel {
            id: id.to_string(),
            name: None,
            text: None,
            number: None,
            text_parameter_ref: None,
            children,
        }
    }

    fn choose(param_ref_id: &str, whens: Vec<(WhenTest, Vec<DynamicNode>)>) -> DynamicNode {
        DynamicNode::Choose {
            param_ref_id: param_ref_id.to_string(),
            whens: whens
                .into_iter()
                .map(|(test, children)| DynamicWhen { test, children })
                .collect(),
        }
    }

    fn pref(r: &str) -> DynamicNode {
        DynamicNode::ParameterRefRef(r.to_string())
    }

    /// `CH-1 > PB-1` shows the selector `P-1_R-1`; `sel = 1` opens `PB-2`
    /// (with `P-2_R-2` and object `O-1_R-1`); any other value shows `P-3_R-3`
    /// in `PB-1`. `P-2_R-2` also sits in the module body `MD-1`, which two
    /// `<Module>`s instantiate.
    fn source() -> TestSource {
        let mut src = TestSource {
            dynamic: vec![channel(
                "CH-1",
                vec![block(
                    "PB-1",
                    vec![
                        pref("P-1_R-1"),
                        choose(
                            "P-1_R-1",
                            vec![
                                (
                                    WhenTest::Values(vec![1]),
                                    vec![block(
                                        "PB-2",
                                        vec![
                                            pref("P-2_R-2"),
                                            DynamicNode::ComObjectRefRef("O-1_R-1".to_string()),
                                        ],
                                    )],
                                ),
                                (WhenTest::Default, vec![pref("P-3_R-3")]),
                            ],
                        ),
                    ],
                )],
            )],
            ..TestSource::default()
        };
        for m in ["MD-1_M-1", "MD-1_M-2"] {
            src.dynamic.push(DynamicNode::Module {
                id: m.to_string(),
                module_def: "MD-1".to_string(),
                args: HashMap::new(),
                computed_args: Vec::new(),
            });
        }
        src.module_dynamics.insert(
            "MD-1".to_string(),
            vec![block("MD-1_PB-1", vec![pref("MD-1_P-1_R-1")])],
        );
        for (r, p) in [
            ("P-1_R-1", "P-1"),
            ("P-2_R-2", "P-2"),
            ("P-3_R-3", "P-3"),
            ("MD-1_P-1_R-1", "MD-1_P-1"),
        ] {
            src.refs.insert(r.to_string(), (p.to_string(), None));
            src.params.insert(p.to_string(), Some("0".to_string()));
        }
        src
    }

    fn container_ids(cfg: &DynamicConfig) -> Vec<(Option<usize>, &str)> {
        cfg.containers
            .iter()
            .map(|c| (c.placement.module, c.container.id()))
            .collect()
    }

    #[test]
    fn test_evaluate_dynamic_containers_follow_the_taken_branch() {
        let src = source();
        let cfg = evaluate_dynamic(&src, &BTreeMap::new());
        assert_eq!(
            container_ids(&cfg),
            [
                (None, "CH-1"),
                (None, "PB-1"),
                (Some(0), "MD-1_PB-1"),
                (Some(1), "MD-1_PB-1")
            ]
        );
        let overrides = BTreeMap::from([("P-1_R-1".to_string(), "1".to_string())]);
        let cfg = evaluate_dynamic(&src, &overrides);
        let pb2 = cfg
            .containers
            .iter()
            .find(|c| c.container.id() == "PB-2")
            .map(|c| &c.placement);
        assert_eq!(
            pb2.and_then(|p| p.channel.as_ref()).map(|c| c.id.as_str()),
            Some("CH-1")
        );
        assert_eq!(
            pb2.map(|p| p.blocks.iter().map(|b| b.id.as_str()).collect::<Vec<_>>()),
            Some(vec!["PB-1"])
        );
        assert!(matches!(
            cfg.containers.first().map(|c| &c.container),
            Some(Container::Channel(c)) if c.id == "CH-1"
        ));
    }

    #[test]
    fn test_evaluate_dynamic_through_a_reference_matches_the_source() {
        let src = source();
        let overrides = BTreeMap::from([("P-1_R-1".to_string(), "1".to_string())]);
        let direct = evaluate_dynamic(&src, &overrides);
        let by_ref = evaluate_dynamic(&&src, &overrides);
        assert_eq!(direct.parameters, by_ref.parameters);
        assert_eq!(direct.containers, by_ref.containers);
        assert_eq!(direct.value(&src, None, "P-1_R-1").as_deref(), Some("1"));
        assert_eq!(direct.value(&src, None, "P-3_R-3").as_deref(), Some("0"));
    }

    #[test]
    fn test_dynamic_memo_evaluate_shares_one_evaluation_per_value_map() {
        let src = source();
        let other = source();
        let memo = DynamicMemo::new(&src);
        let on = BTreeMap::from([("P-1_R-1".to_string(), "1".to_string())]);
        let first = memo.evaluate(&on);
        let again = memo.evaluate(&on);
        assert!(std::sync::Arc::ptr_eq(&first, &again));
        let direct = evaluate_dynamic(&src, &on);
        assert_eq!(first.parameters, direct.parameters);
        assert_eq!(first.com_objects, direct.com_objects);
        assert_eq!(first.containers, direct.containers);
        assert_eq!(first.parameter_placements, direct.parameter_placements);
        assert_eq!(
            memo.evaluate(&BTreeMap::new()).parameters,
            evaluate_dynamic(&src, &BTreeMap::new()).parameters
        );
        assert_eq!(memo.evaluations(), 2);
        // Another program object is evaluated directly, never memoized.
        assert_eq!(memo.evaluate_for(&other, &on).parameters, direct.parameters);
        assert!(std::sync::Arc::ptr_eq(
            &memo.evaluate_for(&src, &on),
            &first
        ));
        assert_eq!(memo.evaluations(), 2);
    }

    #[test]
    fn test_ref_index_new_records_every_occurrence_with_its_gates() {
        let index = RefIndex::new(&source());
        let p2 = index.parameter("P-2_R-2");
        assert_eq!(p2.len(), 1);
        let occ = &p2[0];
        assert_eq!(occ.module_def, None);
        assert_eq!(occ.channel.as_ref().map(|c| c.id.as_str()), Some("CH-1"));
        let blocks: Vec<_> = occ.blocks.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(blocks, ["PB-1", "PB-2"]);
        assert_eq!(
            occ.gates,
            [RefGate {
                param_ref_id: "P-1_R-1".to_string(),
                test: WhenTest::Values(vec![1]),
                siblings: vec![WhenTest::Default],
            }]
        );
        let p3 = index.parameter("P-3_R-3");
        assert_eq!(p3.len(), 1);
        assert_eq!(p3[0].gates[0].test, WhenTest::Default);
        assert_eq!(p3[0].gates[0].siblings, [WhenTest::Values(vec![1])]);
        let blocks: Vec<_> = p3[0].blocks.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(blocks, ["PB-1"]);

        let module = index.parameter("MD-1_P-1_R-1");
        assert_eq!(
            module.len(),
            1,
            "a module body is indexed once, not per instance"
        );
        assert_eq!(module[0].module_def.as_deref(), Some("MD-1"));
        assert!(module[0].gates.is_empty());
        assert_eq!(module[0].channel, None);

        let obj = index.com_object("O-1_R-1");
        assert_eq!(obj.len(), 1);
        assert_eq!(obj[0].gates.len(), 1);
        assert!(index.parameter("P-9_R-9").is_empty());
        let refs: Vec<_> = index.parameters().map(|(r, _)| r).collect();
        assert_eq!(refs, ["MD-1_P-1_R-1", "P-1_R-1", "P-2_R-2", "P-3_R-3"]);
    }

    #[test]
    fn test_ref_index_new_keeps_both_branches_of_a_ref() {
        let src = TestSource {
            dynamic: vec![choose(
                "P-1_R-1",
                vec![
                    (WhenTest::Values(vec![0]), vec![pref("P-2_R-2")]),
                    (
                        WhenTest::Compare {
                            op: CompareOp::Ge,
                            value: 2,
                        },
                        vec![block("PB-7", vec![pref("P-2_R-2")])],
                    ),
                ],
            )],
            ..TestSource::default()
        };
        let index = RefIndex::new(&src);
        let occs = index.parameter("P-2_R-2");
        assert_eq!(occs.len(), 2);
        assert_eq!(occs[0].gates[0].test, WhenTest::Values(vec![0]));
        assert!(occs[0].blocks.is_empty());
        assert_eq!(
            occs[1].gates[0].test,
            WhenTest::Compare {
                op: CompareOp::Ge,
                value: 2
            }
        );
        assert_eq!(occs[1].blocks.len(), 1);
        // The first sits behind its gate outside any container, the second
        // behind it outside PB-7: nothing inside its container gates it.
        assert_eq!(occs[0].container_gates, 0);
        assert_eq!(occs[1].container_gates, 1);
    }

    #[test]
    fn test_ref_gate_holds_values_compare_and_default() {
        let gate = |test: WhenTest, siblings: Vec<WhenTest>| RefGate {
            param_ref_id: "P-1_R-1".to_string(),
            test,
            siblings,
        };
        assert!(gate(WhenTest::Values(vec![1, 2]), vec![]).holds(Some(2.0)));
        assert!(!gate(WhenTest::Values(vec![1]), vec![]).holds(Some(0.0)));
        assert!(!gate(WhenTest::Values(vec![1]), vec![]).holds(None));
        let ne = WhenTest::Compare {
            op: CompareOp::Ne,
            value: 0,
        };
        assert!(gate(ne.clone(), vec![]).holds(Some(3.0)));
        assert!(!gate(ne, vec![]).holds(Some(0.0)));
        let default = gate(WhenTest::Default, vec![WhenTest::Values(vec![1])]);
        assert!(default.holds(Some(0.0)));
        assert!(!default.holds(Some(1.0)));
    }

    #[test]
    fn test_split_selector_inverts_selector_key_for_repetitions_and_submodules() {
        for (instance, reference, key) in [
            (
                "MD-15_M-26",
                "MD-15_UP-22_R-27",
                "MD-15_M-26_MI-1_UP-22_R-27",
            ),
            ("MD-1_M-1_MI-2", "MD-1_P-3_R-5", "MD-1_M-1_MI-2_P-3_R-5"),
            (
                "MD-1_M-1_MI-1_SM-1_M-1_MI-3",
                "MD-1_SM-1_P-1_R-1",
                "MD-1_M-1_MI-1_SM-1_M-1_MI-3_P-1_R-1",
            ),
        ] {
            assert_eq!(selector_key(Some(instance), reference), key);
            assert_eq!(
                split_selector(key),
                (Some(instance.to_string()), reference.to_string())
            );
        }
        assert_eq!(split_selector("P-1_R-1"), (None, "P-1_R-1".to_string()));
        assert_eq!(
            split_selector("MD-1_P-1_R-1"),
            (None, "MD-1_P-1_R-1".to_string())
        );
    }

    #[test]
    fn test_taken_branches_matches_else_defaults() {
        let tests = [
            WhenTest::Values(vec![0]),
            WhenTest::Compare {
                op: CompareOp::Ge,
                value: 2,
            },
            WhenTest::Default,
            WhenTest::Values(vec![3]),
        ];
        // Every matching branch is taken, the default one is not.
        assert_eq!(taken_branches(&tests, Some(3.0)), vec![1, 3]);
        assert_eq!(taken_branches(&tests, Some(0.0)), vec![0]);
        // No match: the default branch.
        assert_eq!(taken_branches(&tests, Some(1.0)), vec![2]);
        // A fractional value matches no exact test.
        assert_eq!(taken_branches(&tests[..1], Some(0.5)), Vec::<usize>::new());
        // No value: only the default branch.
        assert_eq!(taken_branches(&tests, None), vec![2]);
        assert_eq!(
            taken_branches(&[WhenTest::Unknown("x".to_string())], Some(1.0)),
            Vec::<usize>::new()
        );
    }
}
