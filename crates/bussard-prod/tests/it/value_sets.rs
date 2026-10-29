//! The applications and the random value sets the evaluator tests compare
//! under (issue #345): the fixture applications, a seeded generator of
//! valid value sets, and the corpus archives. Shared with
//! `bussard-download`'s view acceptance test, which includes this file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use bussard_prod::ApplicationProgram;

/// The fixture applications: (application id, XML).
pub const FIXTURES: &[(&str, &[u8])] = &[
    (
        "M-00FA_A-0298-10-0000",
        include_bytes!("../fixtures/blocks_app.xml"),
    ),
    (
        "A",
        include_bytes!("../../../bussard-download/tests/fixtures/param-readback/app.xml"),
    ),
    (
        "M-00FA_A-00D1-10-0001",
        include_bytes!("../../../bussard-project/tests/fixtures/dynamic_tree.app.xml"),
    ),
    (
        "M-00FA_A-00D2-10-0001",
        include_bytes!("../../../bussard-project/tests/fixtures/default_params.app.xml"),
    ),
    (
        "M-00FA_A-00D1-10-0001",
        include_bytes!("../../../bussard-ets/tests/fixtures/dynamic_tree.app.xml"),
    ),
    (
        "M-00FA_A-0449-10-0000",
        include_bytes!("../fixtures/allocators.app.xml"),
    ),
];

/// A small seeded generator (SplitMix64) for the random value sets.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number below `n` (0 for `n` 0).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    /// True once in `n` draws.
    pub fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }
}

/// How many random value sets each application is compared under, besides
/// the vendor defaults.
pub const RANDOM_SETS: u64 = 50;

/// One parameter ref a value set may set: its device-file keys (the ref
/// itself, or one per module instance with the selector), the values its
/// type allows and the values its `<choose>` tests name.
pub struct Candidate {
    keys: Vec<String>,
    codes: Vec<i64>,
    range: Option<(i64, i64)>,
    tested: Vec<i64>,
    controls: bool,
}

/// The values each `<choose>` ref's tests name, and every module instance
/// with its definition.
pub type TreeFacts = (BTreeMap<String, BTreeSet<i64>>, Vec<(String, String)>);

/// Every `<choose>` ref with the values its tests name (and their
/// neighbours, for the comparisons), every `<Assign>` source, and every
/// module instance with its definition.
pub fn tree_facts(app: &ApplicationProgram) -> TreeFacts {
    use bussard_prod::dynamic::{DynamicNode, WhenTest};
    fn visit(
        nodes: &[DynamicNode],
        tested: &mut BTreeMap<String, BTreeSet<i64>>,
        modules: &mut Vec<(String, String)>,
    ) {
        for node in nodes {
            match node {
                DynamicNode::Choose {
                    param_ref_id,
                    whens,
                } => {
                    let set = tested.entry(param_ref_id.clone()).or_default();
                    for w in whens {
                        match &w.test {
                            WhenTest::Values(vs) => set.extend(vs.iter().copied()),
                            WhenTest::Compare { value, .. } => set.extend([
                                value.saturating_sub(1),
                                *value,
                                value.saturating_add(1),
                            ]),
                            WhenTest::Default | WhenTest::Unknown(_) => {}
                        }
                    }
                    for w in whens {
                        visit(&w.children, tested, modules);
                    }
                }
                DynamicNode::Channel { children, .. }
                | DynamicNode::ParameterBlock { children, .. } => visit(children, tested, modules),
                DynamicNode::Repeat {
                    param_ref_id,
                    children,
                    ..
                } => {
                    if let Some(r) = param_ref_id {
                        tested.entry(r.clone()).or_default().extend([0, 1, 2]);
                    }
                    visit(children, tested, modules);
                }
                DynamicNode::Module { id, module_def, .. } => {
                    modules.push((id.clone(), module_def.clone()))
                }
                DynamicNode::Assign {
                    source: Some(source),
                    ..
                } => {
                    tested.entry(source.clone()).or_default();
                }
                DynamicNode::ParameterRefRef(_)
                | DynamicNode::ComObjectRefRef(_)
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    let mut tested = BTreeMap::new();
    let mut modules = Vec::new();
    visit(&app.dynamic, &mut tested, &mut modules);
    let mut defs: Vec<&String> = app.module_dynamics.keys().collect();
    defs.sort();
    for def in defs {
        if let Some(body) = app.module_dynamics.get(def) {
            visit(body, &mut tested, &mut modules);
        }
    }
    modules.sort();
    modules.dedup();
    (tested, modules)
}

/// The refs a random value set draws from.
pub fn candidates(app: &ApplicationProgram) -> Vec<Candidate> {
    let (tested, modules) = tree_facts(app);
    let prefix = format!("{}_", app.id);
    let mut out = Vec::new();
    let mut refs: Vec<&bussard_prod::ParameterRef> = app.parameter_refs.values().collect();
    refs.sort_by(|a, b| a.id.cmp(&b.id));
    for pref in refs {
        let Some(rel) = pref.id.strip_prefix(&prefix) else {
            continue;
        };
        let Some(kind) = app
            .parameters
            .get(&pref.ref_id)
            .and_then(|p| p.parameter_type.as_deref())
            .and_then(|t| app.parameter_types.get(t))
            .map(|t| &t.kind)
        else {
            continue;
        };
        let (codes, range) = match kind {
            bussard_prod::ParameterType::Enum { values, .. } => {
                (values.iter().map(|v| v.value).collect(), None)
            }
            bussard_prod::ParameterType::Int { min, max, .. } => {
                let lo = min.unwrap_or(0);
                (
                    Vec::new(),
                    Some((lo, max.unwrap_or(lo.saturating_add(255)))),
                )
            }
            _ => continue,
        };
        let keys: Vec<String> = match rel.split_once('_') {
            Some((md, _)) if md.starts_with("MD-") => modules
                .iter()
                .filter(|(_, def)| def == md)
                .map(|(instance, _)| bussard_prod::dynamic::selector_key(Some(instance), rel))
                .collect(),
            _ => vec![rel.to_string()],
        };
        if keys.is_empty() {
            continue;
        }
        let (controls, tested) = match tested.get(rel) {
            Some(values) => (true, values.iter().copied().collect()),
            None => (false, Vec::new()),
        };
        out.push(Candidate {
            keys,
            codes,
            range,
            tested,
            controls,
        });
    }
    out
}

/// One random valid value set: each controlling ref (a `<choose>` or an
/// `<Assign>` source) in each of its scopes with a chance of one in two,
/// any other ref with one in sixteen; the value one of the enumeration's
/// codes or within the integer range, a tested value half of the time.
pub fn random_values(candidates: &[Candidate], rng: &mut Rng) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for c in candidates {
        for key in &c.keys {
            if !rng.one_in(if c.controls { 2 } else { 16 }) {
                continue;
            }
            let allowed = |v: &i64| match c.range {
                Some((lo, hi)) => (lo..=hi).contains(v),
                None => c.codes.contains(v),
            };
            let tested: Vec<i64> = c.tested.iter().copied().filter(allowed).collect();
            let value = if !tested.is_empty() && rng.one_in(2) {
                tested[rng.below(tested.len() as u64) as usize]
            } else if let Some((lo, hi)) = c.range {
                let span = hi.saturating_sub(lo).max(0) as u64;
                lo.saturating_add(rng.below(span.saturating_add(1)) as i64)
            } else if c.codes.is_empty() {
                continue;
            } else {
                c.codes[rng.below(c.codes.len() as u64) as usize]
            };
            out.insert(key.clone(), value.to_string());
        }
    }
    out
}

/// The `.knxprod` archives at or one level under `dir`, sorted.
pub fn knxprod_files(dir: &Path) -> Vec<PathBuf> {
    let is_knxprod = |p: &Path| p.extension().and_then(|e| e.to_str()) == Some("knxprod");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            for sub in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                if is_knxprod(&sub.path()) {
                    out.push(sub.path());
                }
            }
        } else if is_knxprod(&path) {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The seed of an application's random value sets: its id, hashed.
pub fn seed(app: &ApplicationProgram) -> u64 {
    app.id
        .bytes()
        .fold(0xC0FF_EE00_u64, |h, b| h.rotate_left(5) ^ u64::from(b))
}

/// The vendor directory of the corpus `BUSSARD_PRODUCT_CORPUS` names (the
/// product-corpus directory, its `cache/`, or the vendor directory itself).
/// `None`, with the reason on stderr, when the variable is unset or empty
/// (CI exports it empty on an ordinary run) or when no `.knxprod` is found:
/// a corpus sweep then skips green, as `flash_corpus.rs` does.
pub fn corpus_vendor() -> Option<PathBuf> {
    let dir = std::env::var_os("BUSSARD_PRODUCT_CORPUS")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let Some(dir) = dir else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping the corpus sweep.");
        return None;
    };
    let found = [dir.join("cache/vendor"), dir.join("vendor"), dir.clone()]
        .into_iter()
        .find(|d| !knxprod_files(d).is_empty());
    if found.is_none() {
        eprintln!(
            "BUSSARD_PRODUCT_CORPUS={} holds no .knxprod files; skipping (nothing to sweep). \
             Run tests-support/product-corpus/fetch.sh first.",
            dir.display()
        );
    }
    found
}
