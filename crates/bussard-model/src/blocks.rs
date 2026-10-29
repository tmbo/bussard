//! The ETS parameter pages of an application program (issue #298): the
//! `<ParameterBlock>` and `<Channel>` containers of its Dynamic section.
//!
//! [`pages_of`] derives one [`BlockDef`] per container of the application's
//! own Dynamic section (the product model's `dynamic:` tree, issue #345), in
//! document order (the order ETS lists the pages in): its title, the
//! enclosing block, the `<choose>`/`<when>` conditions between that enclosing
//! container and the block ([`Gate`]), and the parameter and com-object refs
//! it holds on any branch. Containers inside a `<ModuleDef>` are not listed.
//!
//! Which of them a device's configuration shows is the Dynamic evaluator's
//! answer ([`crate::dynamic::evaluate_dynamic`], issue #345), not this
//! module's: [`Gate`] is only the words a page condition is written in.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::dynamic::{DynamicNode, WhenTest};
use crate::param_model::ProductModel;

/// What kind of Dynamic container a [`BlockDef`] is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockKind {
    /// A `<ParameterBlock>`: one ETS parameter page or inline group.
    #[default]
    Block,
    /// A `<Channel>`.
    Channel,
}

impl BlockKind {
    fn is_block(&self) -> bool {
        *self == BlockKind::Block
    }
}

/// One `<choose ParamRefId>`/`<when>` condition on the way to a block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate {
    /// The controlling parameter ref, app-relative (`P-2238_R-2238`).
    #[serde(rename = "ref")]
    pub reference: String,
    /// The `<when>` test as written: values (`1`, `1 2`), a comparison
    /// (`!=0`, `<5`), or `default` for a `<when default="true">` branch.
    pub test: String,
    /// For a `default` branch, the tests of its sibling branches: it is taken
    /// when none of them matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub others: Vec<String>,
}

/// One ETS parameter page (`<ParameterBlock>`) or `<Channel>` of an
/// application's Dynamic section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDef {
    /// The element id, app-relative (`PB-7243`, `CH-0`).
    pub id: String,
    /// Block or channel.
    #[serde(default, skip_serializing_if = "BlockKind::is_block")]
    pub kind: BlockKind,
    /// The title ETS shows: the `Text`, else the text of the parameter ref
    /// that titles it, else its `Name`; placeholders removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The `Name` attribute, when it differs from the title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A channel's `Number`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u32>,
    /// The id of the enclosing block or channel, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The id of the enclosing `<Channel>`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The conditions between the enclosing container and this one,
    /// outermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<Gate>,
    /// The parameter refs directly inside (not in a nested block), on any
    /// branch, app-relative, in document order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<String>,
    /// The com-object refs directly inside (`O-22_R-7`), on any branch, in
    /// document order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<String>,
}

/// The pages and channels of `product`'s own Dynamic section, in document
/// order, derived from its tree. Containers inside a `<ModuleDef>` are not
/// walked. Value-free: which of them a configuration shows is the
/// evaluator's answer.
pub fn pages_of(product: &ProductModel) -> Vec<BlockDef> {
    let mut walk = PageWalk {
        product,
        out: Vec::new(),
        seen_params: Vec::new(),
        seen_objects: Vec::new(),
    };
    walk.nodes(&product.dynamic, None, None, &mut Vec::new());
    walk.out
}

/// The [`pages_of`] walk state: the blocks so far, and per block the refs
/// already recorded (to keep each list free of repeats).
struct PageWalk<'a> {
    product: &'a ProductModel,
    out: Vec<BlockDef>,
    seen_params: Vec<HashSet<String>>,
    seen_objects: Vec<HashSet<String>>,
}

impl PageWalk<'_> {
    /// Walks `nodes` inside block `current` (an index into `out`) of channel
    /// `channel`; `gates` are the conditions since `current` began.
    fn nodes(
        &mut self,
        nodes: &[DynamicNode],
        current: Option<usize>,
        channel: Option<&str>,
        gates: &mut Vec<Gate>,
    ) {
        for node in nodes {
            match node {
                DynamicNode::Channel {
                    id,
                    name,
                    text,
                    number,
                    children,
                    ..
                } => {
                    let title = text
                        .as_deref()
                        .map(clean_text)
                        .filter(|t| !t.is_empty())
                        .or_else(|| name.clone());
                    let index = self.push(BlockDef {
                        id: id.clone(),
                        kind: BlockKind::Channel,
                        name: name.clone().filter(|n| Some(n) != title.as_ref()),
                        text: title,
                        number: *number,
                        parent: current.map(|c| self.out[c].id.clone()),
                        channel: None,
                        when: gates.clone(),
                        ..BlockDef::default()
                    });
                    self.nodes(children, Some(index), Some(id), &mut Vec::new());
                }
                DynamicNode::ParameterBlock {
                    id,
                    name,
                    text,
                    param_ref,
                    children,
                    ..
                } => {
                    let title = text
                        .as_deref()
                        .map(clean_text)
                        .filter(|t| !t.is_empty())
                        .or_else(|| param_ref.as_deref().and_then(|r| self.ref_text(r)))
                        .or_else(|| name.clone());
                    let index = self.push(BlockDef {
                        id: id.clone(),
                        kind: BlockKind::Block,
                        name: name.clone().filter(|n| Some(n) != title.as_ref()),
                        text: title,
                        number: None,
                        parent: current.map(|c| self.out[c].id.clone()),
                        channel: channel.map(str::to_string),
                        when: gates.clone(),
                        ..BlockDef::default()
                    });
                    self.nodes(children, Some(index), channel, &mut Vec::new());
                }
                DynamicNode::ParameterRefRef(reference) => {
                    let Some(c) = current else { continue };
                    if self.seen_params[c].insert(reference.clone()) {
                        self.out[c].parameters.push(reference.clone());
                    }
                }
                DynamicNode::ComObjectRefRef(reference) => {
                    let Some(c) = current else { continue };
                    if self.seen_objects[c].insert(reference.clone()) {
                        self.out[c].objects.push(reference.clone());
                    }
                }
                DynamicNode::Choose {
                    param_ref_id,
                    whens,
                } => {
                    let explicit: Vec<&WhenTest> = whens
                        .iter()
                        .map(|w| &w.test)
                        .filter(|t| **t != WhenTest::Default)
                        .collect();
                    for when in whens {
                        let is_default = when.test == WhenTest::Default;
                        gates.push(Gate {
                            reference: param_ref_id.clone(),
                            test: test_string(&when.test),
                            others: if is_default {
                                explicit.iter().map(|t| test_string(t)).collect()
                            } else {
                                Vec::new()
                            },
                        });
                        self.nodes(&when.children, current, channel, gates);
                        gates.pop();
                    }
                }
                // A repeated body's pages are the body's own (its modules
                // are expanded by the evaluator, not here).
                DynamicNode::Repeat { children, .. } => {
                    self.nodes(children, current, channel, gates);
                }
                DynamicNode::Module { .. } | DynamicNode::Assign { .. } => {}
            }
        }
    }

    fn push(&mut self, block: BlockDef) -> usize {
        self.out.push(block);
        self.seen_params.push(HashSet::new());
        self.seen_objects.push(HashSet::new());
        self.out.len() - 1
    }

    /// The text of an app-relative parameter ref: the ref's own text, else
    /// its parameter's text, else its name.
    fn ref_text(&self, reference: &str) -> Option<String> {
        let pref = self.product.parameter_refs.get(reference)?;
        let param = self.product.parameters.get(&pref.parameter);
        pref.text
            .clone()
            .or_else(|| param.and_then(|p| p.text.clone()))
            .or_else(|| param.and_then(|p| p.name.clone()))
            .map(|t| clean_text(&t))
            .filter(|t| !t.is_empty())
    }
}

/// A `<when>` test as [`Gate::test`] writes it.
fn test_string(test: &WhenTest) -> String {
    match test {
        WhenTest::Default => "default".to_string(),
        // Kept recognisable and matching nothing.
        WhenTest::Unknown(raw) => format!("?{raw}"),
        other => crate::dynamic_compact::test_text(other).unwrap_or_default(),
    }
}

/// A title without its `{{…}}` placeholders: `{{0:default}}` becomes its
/// default text, any other token goes, and the space or `()` it leaves too.
pub fn clean_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let token = &after[..close];
        if let Some((_, default)) = token.split_once(':') {
            out.push_str(default);
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    let out = out.replace("()", "");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The com-object number of a com-object ref (`O-22_R-7` → 22,
/// `MD-1_O-3_R-4` → 3).
pub fn object_number(reference: &str) -> Option<u16> {
    let start = reference.rfind("O-")? + 2;
    let digits: String = reference[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// The parameter id of an app-level parameter ref (`P-2238_R-2238` →
/// `P-2238`).
pub fn ref_param_id(reference: &str) -> &str {
    reference
        .rsplit_once("_R-")
        .map_or(reference, |(head, _)| head)
}

/// The index of each block's parent in `blocks` (the first block with that
/// id that precedes it).
pub fn parent_indexes(blocks: &[BlockDef]) -> Vec<Option<usize>> {
    let mut first: HashMap<&str, usize> = HashMap::new();
    let mut out = Vec::with_capacity(blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        out.push(b.parent.as_deref().and_then(|p| first.get(p).copied()));
        first.entry(b.id.as_str()).or_insert(i);
    }
    out
}

/// The indexes of `index` and every block nested in it, in order.
pub fn subtree(blocks: &[BlockDef], parents: &[Option<usize>], index: usize) -> Vec<usize> {
    let mut inside: Vec<bool> = vec![false; blocks.len()];
    let mut out = Vec::new();
    for i in index..blocks.len() {
        let member = i == index || parents[i].is_some_and(|p| inside[p]);
        if member {
            inside[i] = true;
            out.push(i);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(id: &str, parent: Option<&str>, when: &[(&str, &str)], params: &[&str]) -> BlockDef {
        BlockDef {
            id: id.to_string(),
            parent: parent.map(str::to_string),
            when: when
                .iter()
                .map(|(r, t)| Gate {
                    reference: r.to_string(),
                    test: t.to_string(),
                    others: Vec::new(),
                })
                .collect(),
            parameters: params.iter().map(|p| p.to_string()).collect(),
            ..BlockDef::default()
        }
    }

    #[test]
    fn test_clean_text_drops_placeholders() {
        assert_eq!(clean_text("Kanal {{ArgNr}} ({{0:...}})"), "Kanal (...)");
        assert_eq!(clean_text("Kanal {{0}}"), "Kanal");
        assert_eq!(clean_text("Plain"), "Plain");
    }

    #[test]
    fn test_test_string_round_trips_through_when_test() {
        use crate::dynamic::CompareOp;
        for test in [
            WhenTest::Values(vec![1, 2]),
            WhenTest::Compare {
                op: CompareOp::Ne,
                value: 0,
            },
        ] {
            assert_eq!(WhenTest::parse(Some(&test_string(&test)), None), test);
        }
    }

    #[test]
    fn test_object_number_and_param_id() {
        assert_eq!(object_number("O-22_R-7"), Some(22));
        assert_eq!(object_number("MD-1_O-3_R-4"), Some(3));
        assert_eq!(ref_param_id("P-2238_R-2238"), "P-2238");
    }

    #[test]
    fn test_subtree_follows_nesting() {
        let blocks = vec![
            block("PB-1", None, &[], &[]),
            block("PB-2", Some("PB-1"), &[], &[]),
            block("PB-3", Some("PB-2"), &[], &[]),
            block("PB-4", None, &[], &[]),
        ];
        let parents = parent_indexes(&blocks);
        assert_eq!(subtree(&blocks, &parents, 0), vec![0, 1, 2]);
        assert_eq!(subtree(&blocks, &parents, 3), vec![3]);
    }
}
