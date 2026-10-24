//! The `blocks:` section of a product model (issue #298): the ETS parameter
//! pages and channels of an application's Dynamic section, with the
//! conditions that show them. See [`bussard_model::blocks`] for the shape and
//! for how a device's configuration decides which of them it shows.

use std::collections::{BTreeMap, HashSet};

use bussard_ets::application::{CompareOp, DynamicNode, WhenTest};
use bussard_model::blocks::{BlockDef, BlockKind, Gate};

use crate::ApplicationProgram;

/// The blocks and channels of `app`'s own Dynamic section, in document order.
/// Containers inside a `<ModuleDef>` are not walked.
pub fn blocks_for(app: &ApplicationProgram) -> Vec<BlockDef> {
    let mut walk = Walk {
        app,
        out: Vec::new(),
        seen_params: Vec::new(),
        seen_objects: Vec::new(),
    };
    let mut gates = Vec::new();
    walk.nodes(&app.dynamic, None, None, &mut gates, true);
    walk.out
}

/// The `ParameterRef` `Value` overrides of the refs `blocks` name, in a
/// page or in a condition, keyed by app-relative ref id: the value ETS gives
/// a ref when nothing is stored, where it differs from the parameter's own
/// default (issue #326). A `<choose>` on such a ref (a union steering member
/// like the Meteodata's "Wenn Temperatur" = Windsensor) opens the branch the
/// ref's value names, as the download side evaluates it.
pub fn ref_values_for(app: &ApplicationProgram, blocks: &[BlockDef]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let named = blocks.iter().flat_map(|b| {
        let gates = b
            .when
            .iter()
            .chain(b.parameter_when.values().flatten())
            .map(|g| &g.reference);
        b.parameters.iter().chain(gates)
    });
    for reference in named {
        if out.contains_key(reference) {
            continue;
        }
        let Some(pref) = app.parameter_ref(reference) else {
            continue;
        };
        let Some(value) = pref.value.as_ref() else {
            continue;
        };
        let default = app
            .parameters
            .get(&pref.ref_id)
            .and_then(|p| p.default.as_ref());
        if default != Some(value) {
            out.insert(reference.clone(), value.clone());
        }
    }
    out
}

/// The walk state: the blocks so far, and per block the refs already
/// recorded (to keep each list free of repeats).
struct Walk<'a> {
    app: &'a ApplicationProgram,
    out: Vec<BlockDef>,
    seen_params: Vec<HashSet<String>>,
    seen_objects: Vec<HashSet<String>>,
}

impl Walk<'_> {
    /// Walks `nodes` inside block `current` (an index into `out`) of channel
    /// `channel`. `gates` are the conditions since `current` began, and
    /// `defaults` whether the vendor defaults reach this point from the start
    /// of `current`.
    fn nodes(
        &mut self,
        nodes: &[DynamicNode],
        current: Option<usize>,
        channel: Option<&str>,
        gates: &mut Vec<Gate>,
        defaults: bool,
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
                    // Inside a container the defaults apply afresh: whether the
                    // container itself shows is decided by its `when`.
                    self.nodes(children, Some(index), Some(id), &mut Vec::new(), true);
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
                    self.nodes(children, Some(index), channel, &mut Vec::new(), true);
                }
                DynamicNode::ParameterRefRef(reference) => {
                    let Some(c) = current else { continue };
                    if self.seen_params[c].insert(reference.clone()) {
                        self.out[c].parameters.push(reference.clone());
                        if !gates.is_empty() {
                            self.out[c]
                                .parameter_when
                                .insert(reference.clone(), gates.clone());
                        }
                    } else if self.out[c]
                        .parameter_when
                        .get(reference)
                        .is_some_and(|g| g != gates)
                    {
                        // On another branch too: no one condition shows it.
                        self.out[c].parameter_when.remove(reference);
                    }
                }
                DynamicNode::ComObjectRefRef(reference) => {
                    let Some(c) = current else { continue };
                    if !self.seen_objects[c].insert(reference.clone()) {
                        // Seen before: promote it when the defaults reach it now.
                        if defaults && self.out[c].other_objects.contains(reference) {
                            self.out[c].other_objects.retain(|r| r != reference);
                            self.out[c].objects.push(reference.clone());
                        }
                        continue;
                    }
                    if defaults {
                        self.out[c].objects.push(reference.clone());
                    } else {
                        self.out[c].other_objects.push(reference.clone());
                    }
                }
                DynamicNode::Choose {
                    param_ref_id,
                    whens,
                } => {
                    let value = self.default_value(param_ref_id);
                    let explicit: Vec<&WhenTest> = whens
                        .iter()
                        .map(|w| &w.test)
                        .filter(|t| **t != WhenTest::Default)
                        .collect();
                    let any_match = value.is_some_and(|v| explicit.iter().any(|t| t.matches(v)));
                    for when in whens {
                        let is_default = when.test == WhenTest::Default;
                        let taken = if is_default {
                            !any_match
                        } else {
                            value.is_some_and(|v| when.test.matches(v))
                        };
                        gates.push(Gate {
                            reference: param_ref_id.clone(),
                            test: test_string(&when.test),
                            others: if is_default {
                                explicit.iter().map(|t| test_string(t)).collect()
                            } else {
                                Vec::new()
                            },
                        });
                        self.nodes(&when.children, current, channel, gates, defaults && taken);
                        gates.pop();
                    }
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
        let pref = self.app.parameter_ref(reference)?;
        let param = self.app.parameters.get(&pref.ref_id);
        pref.text
            .clone()
            .or_else(|| param.and_then(|p| p.text.clone()))
            .or_else(|| param.and_then(|p| p.name.clone()))
            .map(|t| clean_text(&t))
            .filter(|t| !t.is_empty())
    }

    /// The vendor default of an app-relative parameter ref, as an integer.
    fn default_value(&self, reference: &str) -> Option<i64> {
        let pref = self.app.parameter_ref(reference)?;
        let raw = pref.value.clone().or_else(|| {
            self.app
                .parameters
                .get(&pref.ref_id)
                .and_then(|p| p.default.clone())
        })?;
        let raw = raw.trim();
        raw.parse::<i64>().ok().or_else(|| {
            raw.parse::<f64>()
                .ok()
                .filter(|f| f.fract() == 0.0)
                .map(|f| f as i64)
        })
    }
}

/// A `<when>` test as [`Gate::test`] writes it.
fn test_string(test: &WhenTest) -> String {
    match test {
        WhenTest::Values(values) => values
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(" "),
        WhenTest::Compare { op, value } => {
            let op = match op {
                CompareOp::Ne => "!=",
                CompareOp::Lt => "<",
                CompareOp::Le => "<=",
                CompareOp::Gt => ">",
                CompareOp::Ge => ">=",
            };
            format!("{op}{value}")
        }
        WhenTest::Default => "default".to_string(),
        // Kept recognisable and matching nothing.
        WhenTest::Unknown(raw) => format!("?{raw}"),
    }
}

/// A title without its `{{…}}` placeholders: `{{0:default}}` becomes its
/// default text, any other token goes, and the space or `()` it leaves too.
fn clean_text(text: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_text_drops_placeholders() {
        assert_eq!(clean_text("Kanal {{ArgNr}} ({{0:...}})"), "Kanal (...)");
        assert_eq!(clean_text("Kanal {{0}}"), "Kanal");
        assert_eq!(clean_text("Plain"), "Plain");
    }

    #[test]
    fn test_test_string_round_trips_through_gate() {
        let gate = Gate {
            reference: "P-1_R-1".into(),
            test: test_string(&WhenTest::Values(vec![1, 2])),
            others: Vec::new(),
        };
        assert!(gate.holds(Some(2.0)));
        let gate = Gate {
            reference: "P-1_R-1".into(),
            test: test_string(&WhenTest::Compare {
                op: CompareOp::Ne,
                value: 0,
            }),
            others: Vec::new(),
        };
        assert!(gate.holds(Some(5.0)) && !gate.holds(Some(0.0)));
    }
}
