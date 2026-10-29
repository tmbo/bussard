//! The compact serde form of a Dynamic tree, as the product model carries it
//! (`dynamic:`, `module_dynamics:` and `unions:`, model format 5, issue #345).
//!
//! [`DynamicNode`]'s own derive is the verbose externally tagged form the
//! parsed-product cache stores. The product model is read by people and
//! loaded on every command, so it uses short keys instead, one map per node:
//!
//! ```yaml
//! - p: P-1_R-1                      # <ParameterRefRef>
//! - o: O-1_R-1                      # <ComObjectRefRef>
//! - choose:
//!     ref: P-1_R-1
//!     when:
//!     - test: '1 2'                 # or `!=0`, `<5`, ...
//!       nodes: [...]
//!     - default: true
//!       nodes: [...]
//! - block: {id, name, text, text_ref, param_ref, nodes}
//! - channel: {id, name, text, number, text_ref, nodes}
//! - module: {id, def, args: {MD-1_A-1: 4},
//!            computed: [{arg, allocator, value, base}]}
//! - repeat: {id, ref, count, nodes}  # <Repeat>
//! - assign: {target, source, value}
//! ```
//!
//! Absent attributes, empty `nodes` and empty `args` are left out. A test is
//! written as ETS writes it and read back through [`WhenTest::parse`], which
//! gives the same [`WhenTest`] (the round trip is pinned by the evaluator
//! conformance test in `bussard-prod`).
//!
//! The submodules are `#[serde(with = ...)]` adapters: [`nodes`] for a
//! `Vec<DynamicNode>`, [`module_nodes`] for the module definitions' bodies,
//! [`unions`] for the `<Union>` layouts.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize, Serializer};

use crate::dynamic::{
    CompareOp, ComputedArg, DynamicNode, DynamicWhen, Union, UnionMember, WhenTest,
};

/// A borrowed node list, serialized in the compact form.
struct NodesOut<'a>(&'a [DynamicNode]);

impl Serialize for NodesOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(node_out))
    }
}

/// Whether a node list is empty (the `nodes` key is then left out).
fn no_nodes(nodes: &NodesOut<'_>) -> bool {
    nodes.0.is_empty()
}

/// One node as written: a one-key map. A struct of optional fields rather
/// than an enum, because the YAML emitter writes an enum variant as a tag
/// (`!p P-1_R-1`), not as a key.
#[derive(Default, Serialize)]
struct NodeOut<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    p: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    o: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    choose: Option<ChooseOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block: Option<BlockOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<ChannelOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<ModuleOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repeat: Option<RepeatOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assign: Option<AssignOut<'a>>,
}

#[derive(Serialize)]
struct RepeatOut<'a> {
    id: &'a str,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    reference: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<u32>,
    #[serde(skip_serializing_if = "no_nodes")]
    nodes: NodesOut<'a>,
}

#[derive(Serialize)]
struct ChooseOut<'a> {
    #[serde(rename = "ref")]
    reference: &'a str,
    when: Vec<WhenOut<'a>>,
}

#[derive(Serialize)]
struct WhenOut<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    test: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    default: bool,
    #[serde(skip_serializing_if = "no_nodes")]
    nodes: NodesOut<'a>,
}

#[derive(Serialize)]
struct BlockOut<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    param_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "no_nodes")]
    nodes: NodesOut<'a>,
}

#[derive(Serialize)]
struct ChannelOut<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "no_nodes")]
    nodes: NodesOut<'a>,
}

#[derive(Serialize)]
struct ModuleOut<'a> {
    id: &'a str,
    def: &'a str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    args: BTreeMap<&'a str, i64>,
    #[serde(skip_serializing_if = "<[ComputedArg]>::is_empty")]
    computed: &'a [ComputedArg],
}

#[derive(Serialize)]
struct AssignOut<'a> {
    target: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
}

/// The `test` text of a branch, `None` for the default branch.
pub(crate) fn test_text(test: &WhenTest) -> Option<String> {
    match test {
        WhenTest::Values(values) => Some(
            values
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        WhenTest::Compare { op, value } => {
            let op = match op {
                CompareOp::Ne => "!=",
                CompareOp::Lt => "<",
                CompareOp::Le => "<=",
                CompareOp::Gt => ">",
                CompareOp::Ge => ">=",
            };
            Some(format!("{op}{value}"))
        }
        WhenTest::Default => None,
        WhenTest::Unknown(raw) => Some(raw.clone()),
    }
}

fn node_out(node: &DynamicNode) -> NodeOut<'_> {
    let mut out = NodeOut::default();
    match node {
        DynamicNode::ParameterRefRef(r) => out.p = Some(r),
        DynamicNode::ComObjectRefRef(r) => out.o = Some(r),
        DynamicNode::Choose {
            param_ref_id,
            whens,
        } => {
            out.choose = Some(ChooseOut {
                reference: param_ref_id,
                when: whens
                    .iter()
                    .map(|w| WhenOut {
                        test: test_text(&w.test),
                        default: w.test == WhenTest::Default,
                        nodes: NodesOut(&w.children),
                    })
                    .collect(),
            })
        }
        DynamicNode::ParameterBlock {
            id,
            name,
            text,
            text_parameter_ref,
            param_ref,
            children,
        } => {
            out.block = Some(BlockOut {
                id,
                name: name.as_deref(),
                text: text.as_deref(),
                text_ref: text_parameter_ref.as_deref(),
                param_ref: param_ref.as_deref(),
                nodes: NodesOut(children),
            })
        }
        DynamicNode::Channel {
            id,
            name,
            text,
            number,
            text_parameter_ref,
            children,
        } => {
            out.channel = Some(ChannelOut {
                id,
                name: name.as_deref(),
                text: text.as_deref(),
                number: *number,
                text_ref: text_parameter_ref.as_deref(),
                nodes: NodesOut(children),
            })
        }
        DynamicNode::Module {
            id,
            module_def,
            args,
            computed_args,
        } => {
            out.module = Some(ModuleOut {
                id,
                def: module_def,
                args: args.iter().map(|(k, v)| (k.as_str(), *v)).collect(),
                computed: computed_args,
            })
        }
        DynamicNode::Repeat {
            id,
            param_ref_id,
            count,
            children,
        } => {
            out.repeat = Some(RepeatOut {
                id,
                reference: param_ref_id.as_deref(),
                count: *count,
                nodes: NodesOut(children),
            })
        }
        DynamicNode::Assign {
            target,
            source,
            value,
        } => {
            out.assign = Some(AssignOut {
                target,
                source: source.as_deref(),
                value: value.as_deref(),
            })
        }
    }
    out
}

/// One node as read: a map with exactly one of these keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeIn {
    #[serde(default)]
    p: Option<String>,
    #[serde(default)]
    o: Option<String>,
    #[serde(default)]
    choose: Option<ChooseIn>,
    #[serde(default)]
    block: Option<BlockIn>,
    #[serde(default)]
    channel: Option<ChannelIn>,
    #[serde(default)]
    module: Option<ModuleIn>,
    #[serde(default)]
    repeat: Option<RepeatIn>,
    #[serde(default)]
    assign: Option<AssignIn>,
}

#[derive(Deserialize)]
struct RepeatIn {
    id: String,
    #[serde(default, rename = "ref")]
    reference: Option<String>,
    #[serde(default)]
    count: Option<u32>,
    #[serde(default)]
    nodes: Vec<NodeIn>,
}

#[derive(Deserialize)]
struct ChooseIn {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default)]
    when: Vec<WhenIn>,
}

#[derive(Deserialize)]
struct WhenIn {
    #[serde(default)]
    test: Option<String>,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    nodes: Vec<NodeIn>,
}

#[derive(Deserialize)]
struct BlockIn {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    text_ref: Option<String>,
    #[serde(default)]
    param_ref: Option<String>,
    #[serde(default)]
    nodes: Vec<NodeIn>,
}

#[derive(Deserialize)]
struct ChannelIn {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    number: Option<u32>,
    #[serde(default)]
    text_ref: Option<String>,
    #[serde(default)]
    nodes: Vec<NodeIn>,
}

#[derive(Deserialize)]
struct ModuleIn {
    id: String,
    def: String,
    #[serde(default)]
    args: HashMap<String, i64>,
    #[serde(default)]
    computed: Vec<ComputedArg>,
}

#[derive(Deserialize)]
struct AssignIn {
    target: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

fn into_nodes<E: serde::de::Error>(nodes: Vec<NodeIn>) -> Result<Vec<DynamicNode>, E> {
    nodes.into_iter().map(into_node).collect()
}

fn into_node<E: serde::de::Error>(node: NodeIn) -> Result<DynamicNode, E> {
    let NodeIn {
        p,
        o,
        choose,
        block,
        channel,
        module,
        repeat,
        assign,
    } = node;
    let set = [
        p.is_some(),
        o.is_some(),
        choose.is_some(),
        block.is_some(),
        channel.is_some(),
        module.is_some(),
        repeat.is_some(),
        assign.is_some(),
    ];
    if set.iter().filter(|s| **s).count() != 1 {
        return Err(E::custom(
            "a Dynamic node has exactly one of p, o, choose, block, channel, module, repeat, assign",
        ));
    }
    if let Some(r) = p {
        return Ok(DynamicNode::ParameterRefRef(r));
    }
    if let Some(r) = o {
        return Ok(DynamicNode::ComObjectRefRef(r));
    }
    if let Some(c) = choose {
        let whens = c
            .when
            .into_iter()
            .map(|w| {
                Ok(DynamicWhen {
                    test: WhenTest::parse(w.test.as_deref(), w.default.then_some("true")),
                    children: into_nodes(w.nodes)?,
                })
            })
            .collect::<Result<_, E>>()?;
        return Ok(DynamicNode::Choose {
            param_ref_id: c.reference,
            whens,
        });
    }
    if let Some(b) = block {
        return Ok(DynamicNode::ParameterBlock {
            id: b.id,
            name: b.name,
            text: b.text,
            text_parameter_ref: b.text_ref,
            param_ref: b.param_ref,
            children: into_nodes(b.nodes)?,
        });
    }
    if let Some(c) = channel {
        return Ok(DynamicNode::Channel {
            id: c.id,
            name: c.name,
            text: c.text,
            number: c.number,
            text_parameter_ref: c.text_ref,
            children: into_nodes(c.nodes)?,
        });
    }
    if let Some(m) = module {
        return Ok(DynamicNode::Module {
            id: m.id,
            module_def: m.def,
            args: m.args,
            computed_args: m.computed,
        });
    }
    if let Some(r) = repeat {
        return Ok(DynamicNode::Repeat {
            id: r.id,
            param_ref_id: r.reference,
            count: r.count,
            children: into_nodes(r.nodes)?,
        });
    }
    match assign {
        Some(a) => Ok(DynamicNode::Assign {
            target: a.target,
            source: a.source,
            value: a.value,
        }),
        None => Err(E::custom("an empty Dynamic node")),
    }
}

/// Appends `nodes` to `out` as a YAML block sequence of flow maps, one
/// node (with everything inside it) per line, each line `indent` followed by
/// `- ` and the node in JSON (which YAML reads as a flow map).
///
/// What the product model writer emits for `dynamic:` and `module_dynamics:`:
/// the block form indents every level, and on the deep trees of real
/// programs the indentation is three quarters of the bytes (9.0 MB of block
/// YAML against 2.8 MB this way for the Jung `A-D144`). Read back through
/// [`nodes`] like any other YAML.
///
/// # Errors
///
/// A node does not serialize (never for a well-formed tree).
pub fn write_flow_lines(
    nodes: &[DynamicNode],
    indent: &str,
    out: &mut String,
) -> Result<(), serde_json::Error> {
    for node in nodes {
        out.push_str(indent);
        out.push_str("- ");
        out.push_str(&serde_json::to_string(&node_out(node))?);
        out.push('\n');
    }
    Ok(())
}

/// `#[serde(with)]` adapter for a node list (`dynamic:`).
pub mod nodes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{NodeIn, NodesOut, into_nodes};
    use crate::dynamic::DynamicNode;

    /// Writes `nodes` in the compact form.
    pub fn serialize<S: Serializer>(
        nodes: &[DynamicNode],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        NodesOut(nodes).serialize(serializer)
    }

    /// Reads a node list in the compact form.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<DynamicNode>, D::Error> {
        into_nodes(Vec::<NodeIn>::deserialize(deserializer)?)
    }
}

/// `#[serde(with)]` adapter for the module definitions' bodies keyed by
/// module definition id (`module_dynamics:`).
pub mod module_nodes {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::{NodeIn, NodesOut, into_nodes};
    use crate::dynamic::DynamicNode;

    /// Writes the bodies in the compact form, by module definition id.
    pub fn serialize<S, K, V>(bodies: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: AsRef<str>,
        V: AsRef<[DynamicNode]>,
    {
        serializer.collect_map(
            bodies
                .iter()
                .map(|(k, v)| (k.as_ref(), NodesOut(v.as_ref()))),
        )
    }

    /// Reads the bodies in the compact form.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, Vec<DynamicNode>>, D::Error> {
        BTreeMap::<String, Vec<NodeIn>>::deserialize(deserializer)?
            .into_iter()
            .map(|(k, v)| Ok((k, into_nodes(v)?)))
            .collect()
    }
}

/// One `<Union>` as written: its size and its members' positions, which is
/// all the evaluator reads (the shared memory a reached member's value
/// fills and the other members read back).
#[derive(Serialize, Deserialize)]
struct UnionCompact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size_bits: Option<u32>,
    #[serde(default)]
    members: Vec<UnionMemberCompact>,
}

#[derive(Serialize, Deserialize)]
struct UnionMemberCompact {
    param: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bit_offset: Option<u8>,
}

/// `#[serde(with)]` adapter for the `<Union>` layouts (`unions:`). Only the
/// size and the member positions are kept: the base memory and the
/// `DefaultUnionParameter` mark are the image builder's, which reads the XML.
pub mod unions {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{UnionCompact, UnionMemberCompact};
    use crate::dynamic::Union;

    /// Writes the layouts in the compact form.
    pub fn serialize<S: Serializer>(unions: &[Union], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(unions.iter().map(|u| {
            UnionCompact {
                size_bits: u.size_bits,
                members: u
                    .members
                    .iter()
                    .map(|m| UnionMemberCompact {
                        param: m.parameter.clone(),
                        offset: m.offset,
                        bit_offset: m.bit_offset,
                    })
                    .collect(),
            }
        }))
    }

    /// Reads the layouts in the compact form.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Union>, D::Error> {
        Ok(Vec::<UnionCompact>::deserialize(deserializer)?
            .into_iter()
            .map(super::into_union)
            .collect())
    }
}

fn into_union(u: UnionCompact) -> Union {
    Union {
        size_bits: u.size_bits,
        memory: None,
        members: u
            .members
            .into_iter()
            .map(|m| UnionMember {
                parameter: m.param,
                offset: m.offset,
                bit_offset: m.bit_offset,
                is_default: false,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Doc {
        #[serde(with = "nodes")]
        dynamic: Vec<DynamicNode>,
    }

    #[test]
    fn test_nodes_round_trip_every_shape() -> Result<(), Box<dyn std::error::Error>> {
        let tree = vec![DynamicNode::Channel {
            id: "CH-1".into(),
            name: Some("c".into()),
            text: Some("Channel".into()),
            number: Some(1),
            text_parameter_ref: Some("P-1_R-1".into()),
            children: vec![
                DynamicNode::ParameterRefRef("P-1_R-1".into()),
                DynamicNode::Choose {
                    param_ref_id: "P-1_R-1".into(),
                    whens: [
                        WhenTest::Values(vec![1, -2]),
                        WhenTest::Compare {
                            op: CompareOp::Ne,
                            value: 0,
                        },
                        WhenTest::Unknown("x y".into()),
                        WhenTest::Unknown(String::new()),
                        WhenTest::Default,
                    ]
                    .into_iter()
                    .map(|test| DynamicWhen {
                        test,
                        children: vec![DynamicNode::ComObjectRefRef("O-1_R-1".into())],
                    })
                    .collect(),
                },
                DynamicNode::ParameterBlock {
                    id: "PB-1".into(),
                    name: None,
                    text: None,
                    text_parameter_ref: None,
                    param_ref: Some("P-1_R-1".into()),
                    children: Vec::new(),
                },
                DynamicNode::Module {
                    id: "MD-1_M-1".into(),
                    module_def: "MD-1".into(),
                    args: HashMap::from([("MD-1_A-1".to_string(), 4)]),
                    computed_args: Vec::new(),
                },
                DynamicNode::Repeat {
                    id: "X-1".into(),
                    param_ref_id: Some("P-1_R-1".into()),
                    count: None,
                    children: vec![DynamicNode::Module {
                        id: "MD-2_M-1".into(),
                        module_def: "MD-2".into(),
                        args: HashMap::new(),
                        computed_args: vec![
                            ComputedArg {
                                arg: "MD-2_A-1".into(),
                                allocator: Some("L-1".into()),
                                value: None,
                                base: None,
                            },
                            ComputedArg {
                                arg: "MD-2_A-2".into(),
                                allocator: None,
                                value: Some(0),
                                base: Some("MD-2_A-1".into()),
                            },
                        ],
                    }],
                },
                DynamicNode::Assign {
                    target: "P-2_R-2".into(),
                    source: None,
                    value: Some("3".into()),
                },
            ],
        }];
        let yaml = serde_norway::to_string(&Doc {
            dynamic: tree.clone(),
        })?;
        assert!(yaml.contains("- p: P-1_R-1"), "{yaml}");
        let back: Doc = serde_norway::from_str(&yaml)?;
        assert_eq!(back.dynamic, tree);
        let mut flow = String::from("dynamic:\n");
        write_flow_lines(&tree, "", &mut flow)?;
        assert!(flow.starts_with("dynamic:\n- {\"channel\":"), "{flow}");
        let back: Doc = serde_norway::from_str(&flow)?;
        assert_eq!(back.dynamic, tree);
        let json = serde_json::to_string(&Doc {
            dynamic: tree.clone(),
        })?;
        let back: Doc = serde_json::from_str(&json)?;
        assert_eq!(back.dynamic, tree);
        Ok(())
    }
}
