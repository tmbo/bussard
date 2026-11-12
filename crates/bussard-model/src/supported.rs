//! bussard's device-support list (issues #1089, #1097): per application
//! program a category, `proven`, `likely` or `unsupported`, and the evidence
//! that put it there. Embedded in the binary from two files:
//! `data/supported-devices.toml`, kept by hand (proven devices, house
//! captures), and `data/supported-generated.toml`, computed from the committed
//! ETS sweep by `tools/supported-devices/generate.py`.
//!
//! The list only records the evidence. The verdict a write acts on, and the
//! refusal, live in `bussard-service` (`support`), so the CLI and the MCP
//! server decide the same way.
//!
//! The family rule: a `likely` entry needs a `proven` entry of the same family,
//! and the family key is the mask (the load-procedure shape cannot be derived
//! from committed data yet). [`SupportedList::parse_with`] refuses a list that
//! breaks it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// The hand-kept half of the list, the text the binary embeds.
pub const SUPPORTED_DEVICES_TOML: &str = include_str!("../data/supported-devices.toml");

/// The generated half of the list, the text the binary embeds.
pub const SUPPORTED_GENERATED_TOML: &str = include_str!("../data/supported-generated.toml");

/// Where an application stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// bussard wrote a real device with this application and the read-back
    /// matched.
    Proven,
    /// The evidence says bussard's download matches ETS, but bussard has not
    /// written a real device with this application.
    Likely,
    /// A known problem, or never seen.
    Unsupported,
}

impl Category {
    /// The word the list file and every surface use.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Proven => "proven",
            Category::Likely => "likely",
            Category::Unsupported => "unsupported",
        }
    }

    /// Whether a write passes the gate without the override.
    pub fn passes(self) -> bool {
        matches!(self, Category::Proven | Category::Likely)
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What put an application in its category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Evidence {
    /// Flashed by bussard on a real device and read back.
    Live,
    /// The offline oracle is identical against an ETS capture of a house
    /// device.
    HouseCapture,
    /// The ETS sweep over the product catalogue
    /// (`tools/ets-sweep/evidence/manifest.json`).
    Sweep,
    /// An issue names the problem.
    Issue,
}

impl Evidence {
    /// The word the list file and every surface use.
    pub fn as_str(self) -> &'static str {
        match self {
            Evidence::Live => "live",
            Evidence::HouseCapture => "house-capture",
            Evidence::Sweep => "sweep",
            Evidence::Issue => "issue",
        }
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One application program on the list.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SupportedEntry {
    /// The application id: manufacturer, application number and version as
    /// ten upper-case hex digits (`000420DE22`).
    pub application_id: String,
    /// Manufacturer and product, for messages.
    pub name: String,
    /// Where it stands.
    pub category: Category,
    /// What put it there.
    pub evidence: Evidence,
    /// The device masks of the application's builds, the family keys
    /// (`07B0`); one for every hand-kept entry, and two where the sweep saw
    /// builds of one id on two masks.
    pub masks: Vec<String>,
    /// The citation of a hand-kept entry: an issue or a dated owner
    /// statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The issue that names a known problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<u32>,
    /// Why an `unsupported` entry is refused (`differs from ETS in the
    /// sweep`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The known cause, when an issue names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// The sweep coverage, percent, of a generated `likely` entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<f64>,
    /// The rule a generated `likely` entry passed ([`SupportRule`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Builds of a generated `likely` entry's id the sweep did not capture
    /// (neither for nor against the entry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncompared: Option<u32>,
}

impl SupportedEntry {
    /// The application ref prefix the id stands for (`M-0004_A-20DE-22`).
    pub fn application(&self) -> String {
        application_ref_of(&self.application_id)
    }

    /// The known problem in words: `differs from ETS in the sweep, #971`.
    /// `None` for an entry that passes.
    pub fn problem(&self) -> Option<String> {
        if self.category.passes() {
            return None;
        }
        let reason = self.reason.as_deref().unwrap_or("known problem");
        Some(match self.issue {
            Some(issue) => format!("{reason}, #{issue}"),
            None => reason.to_string(),
        })
    }
}

/// The application ref prefix of a ten-digit application id: `000420DE22`
/// is `M-0004_A-20DE-22`. An id of another shape is returned as it is.
pub fn application_ref_of(application_id: &str) -> String {
    match (
        application_id.get(..4),
        application_id.get(4..8),
        application_id.get(8..),
    ) {
        (Some(m), Some(n), Some(v)) if is_application_id(application_id) => {
            format!("M-{m}_A-{n}-{v}")
        }
        _ => application_id.to_string(),
    }
}

/// Whether `id` has the shape of an application id: ten hex digits.
pub fn is_application_id(id: &str) -> bool {
    id.len() == 10 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// A rule the generator applied to put applications in `likely`: what it
/// checked and, so the docs say honestly what `likely` rests on, what it did
/// not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportRule {
    /// The rule's id (`sweep-1`).
    pub id: String,
    /// The conditions every entry of the rule passed.
    pub checked: Vec<String>,
    /// The conditions the rule does not check yet.
    pub not_checked: Vec<String>,
}

/// What the generator saw of one family (mask) beyond the list's entries.
/// The proven and likely applications of a family are the entries
/// themselves ([`SupportedList::entries`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportFamily {
    /// The mask.
    pub mask: String,
    /// Applications the sweep finds identical that wait for a proven device
    /// of the family.
    pub blocked: u32,
    /// Synthetic products of the family whose every capture is identical.
    pub synthetic: u32,
}

/// Where the generated half comes from.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct SupportSource {
    /// The sweep manifest, a repository path.
    pub sweep_manifest: String,
    /// The manifest's `generated` stamp.
    pub sweep_generated: String,
    /// The synthetic manifest, a repository path.
    pub synthetic_manifest: String,
    /// The coverage floor of the sweep rule, percent.
    pub coverage_floor: f64,
}

/// The hand file's shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandFile {
    /// The entries.
    #[serde(default)]
    device: Vec<HandEntry>,
}

/// A hand-kept entry as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandEntry {
    application_id: String,
    name: String,
    category: Category,
    evidence: Evidence,
    mask: String,
    source: String,
    #[serde(default)]
    issue: Option<u32>,
    #[serde(default)]
    reason: Option<String>,
    /// Where the mask comes from, for an id the sweep never saw (the
    /// generator checks the mask against the sweep otherwise).
    #[serde(default)]
    mask_source: Option<String>,
    /// Why an entry that passes the gate stands although the sweep reports a
    /// build of it differing (the generator refuses the entry otherwise).
    #[serde(default)]
    sweep_differs: Option<String>,
}

/// The generated file's shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedFile {
    source: GeneratedSource,
    #[serde(default)]
    family: Vec<GeneratedFamily>,
    #[serde(default)]
    rule: Vec<GeneratedRule>,
    differs: GeneratedDiffers,
}

/// `[source]` of the generated file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedSource {
    sweep_manifest: String,
    sweep_generated: String,
    synthetic_manifest: String,
    coverage_floor: f64,
}

/// `[[family]]` of the generated file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedFamily {
    mask: String,
    blocked: u32,
    synthetic: u32,
}

/// `[[rule]]` of the generated file, with the entries that passed it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedRule {
    id: String,
    checked: Vec<String>,
    not_checked: Vec<String>,
    likely: Vec<GeneratedLikely>,
}

/// One generated `likely` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedLikely {
    id: String,
    name: String,
    masks: Vec<String>,
    coverage: f64,
    #[serde(default)]
    uncompared: Option<u32>,
}

/// `[differs]` of the generated file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedDiffers {
    reason: String,
    entries: Vec<GeneratedProblem>,
}

/// One application the sweep reports `differs`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedProblem {
    id: String,
    name: String,
    masks: Vec<String>,
    issue: u32,
    cause: String,
}

/// Why a list did not parse.
#[derive(Debug, thiserror::Error)]
pub enum SupportedListError {
    /// The TOML did not parse.
    #[error("supported-device list: {0}")]
    Toml(#[from] toml::de::Error),
    /// An entry is malformed.
    #[error("supported-device list, entry {index} ({application_id}): {reason}")]
    Entry {
        /// The entry's position, from zero.
        index: usize,
        /// The entry's application id as written.
        application_id: String,
        /// What is wrong with it.
        reason: String,
    },
}

/// The device-support list.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SupportedList {
    /// The entries, sorted by application id.
    entries: Vec<SupportedEntry>,
    /// The generator's rules.
    rules: Vec<SupportRule>,
    /// The families the generator saw.
    families: Vec<SupportFamily>,
    /// Where the generated half comes from.
    source: SupportSource,
}

/// Whether `text` cites an issue (`#123`) or a date (`2026-11-12`).
fn cites(text: &str) -> bool {
    let b = text.as_bytes();
    let issue = b.windows(2).any(|w| w[0] == b'#' && w[1].is_ascii_digit());
    let date = b.windows(10).any(|w| {
        w.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
    });
    issue || date
}

/// Whether `mask` is four upper-case hex digits.
fn is_mask(mask: &str) -> bool {
    mask.len() == 4
        && mask
            .chars()
            .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))
}

impl SupportedList {
    /// Parses a hand-kept list alone (no generated half).
    ///
    /// # Errors
    ///
    /// As [`SupportedList::parse_with`].
    pub fn parse(hand: &str) -> Result<SupportedList, SupportedListError> {
        SupportedList::parse_with(hand, None)
    }

    /// Parses the hand-kept half and, when given, the generated half: every
    /// id ten upper-case hex digits and listed once across both, every name
    /// non-empty, every mask four hex digits; a hand entry cites an issue or a
    /// date, `proven` is exactly the `live` evidence, an `unsupported` hand
    /// entry names its issue; and every `likely` entry has a `proven` entry of
    /// its family (mask).
    ///
    /// # Errors
    ///
    /// The TOML does not parse, or an entry is malformed, repeated or breaks
    /// the family rule.
    pub fn parse_with(
        hand: &str,
        generated: Option<&str>,
    ) -> Result<SupportedList, SupportedListError> {
        let file: HandFile = toml::from_str(hand)?;
        let mut entries: Vec<SupportedEntry> = Vec::new();
        for (index, e) in file.device.into_iter().enumerate() {
            let bad = |reason: &str| SupportedListError::Entry {
                index,
                application_id: e.application_id.clone(),
                reason: reason.to_string(),
            };
            if !cites(&e.source) {
                return Err(bad(
                    "source must cite an issue (#123) or a dated owner statement (2026-11-12)",
                ));
            }
            // The combinations a hand entry may have: proven from a live
            // run, likely from a house capture, a known problem from an
            // issue. `sweep` evidence is the generator's.
            let allowed = match e.category {
                Category::Proven => Evidence::Live,
                Category::Likely => Evidence::HouseCapture,
                Category::Unsupported => Evidence::Issue,
            };
            if e.evidence != allowed {
                return Err(bad(&format!(
                    "a hand-kept {} entry has {} evidence",
                    e.category, allowed
                )));
            }
            match e.category {
                Category::Unsupported if e.issue.is_none() || e.reason.is_none() => {
                    return Err(bad("an unsupported entry names its issue and reason"));
                }
                Category::Proven | Category::Likely if e.issue.is_some() || e.reason.is_some() => {
                    return Err(bad(
                        "issue and reason belong to an unsupported entry; this one passes the gate",
                    ));
                }
                _ => {}
            }
            for (field, text) in [
                ("mask_source", &e.mask_source),
                ("sweep_differs", &e.sweep_differs),
            ] {
                if text.as_deref().is_some_and(|t| !cites(t)) {
                    return Err(bad(&format!(
                        "{field} must cite an issue (#123) or a dated owner statement"
                    )));
                }
            }
            entries.push(SupportedEntry {
                application_id: e.application_id,
                name: e.name,
                category: e.category,
                evidence: e.evidence,
                masks: vec![e.mask],
                source: Some(e.source),
                issue: e.issue,
                reason: e.reason,
                cause: None,
                coverage: None,
                rule: None,
                uncompared: None,
            });
        }
        let mut list = SupportedList::default();
        if let Some(text) = generated {
            let file: GeneratedFile = toml::from_str(text)?;
            list.source = SupportSource {
                sweep_manifest: file.source.sweep_manifest,
                sweep_generated: file.source.sweep_generated,
                synthetic_manifest: file.source.synthetic_manifest,
                coverage_floor: file.source.coverage_floor,
            };
            list.families = file
                .family
                .into_iter()
                .map(|f| SupportFamily {
                    mask: f.mask,
                    blocked: f.blocked,
                    synthetic: f.synthetic,
                })
                .collect();
            for rule in file.rule {
                entries.extend(rule.likely.into_iter().map(|e| SupportedEntry {
                    application_id: e.id,
                    name: e.name,
                    category: Category::Likely,
                    evidence: Evidence::Sweep,
                    masks: e.masks,
                    source: None,
                    issue: None,
                    reason: None,
                    cause: None,
                    coverage: Some(e.coverage),
                    rule: Some(rule.id.clone()),
                    uncompared: e.uncompared,
                }));
                list.rules.push(SupportRule {
                    id: rule.id,
                    checked: rule.checked,
                    not_checked: rule.not_checked,
                });
            }
            let reason = file.differs.reason;
            entries.extend(file.differs.entries.into_iter().map(|e| SupportedEntry {
                application_id: e.id,
                name: e.name,
                category: Category::Unsupported,
                evidence: Evidence::Sweep,
                masks: e.masks,
                source: None,
                issue: Some(e.issue),
                reason: Some(reason.clone()),
                cause: Some(e.cause),
                coverage: None,
                rule: None,
                uncompared: None,
            }));
        }
        let proven_masks: BTreeSet<String> = entries
            .iter()
            .filter(|e| e.category == Category::Proven)
            .flat_map(|e| e.masks.iter().cloned())
            .collect();
        for (index, entry) in entries.iter().enumerate() {
            let bad = |reason: String| SupportedListError::Entry {
                index,
                application_id: entry.application_id.clone(),
                reason,
            };
            if !is_application_id(&entry.application_id)
                || entry.application_id.to_ascii_uppercase() != entry.application_id
            {
                return Err(bad(
                    "application_id must be ten upper-case hex digits".to_string()
                ));
            }
            if entry.name.trim().is_empty() {
                return Err(bad("name is empty".to_string()));
            }
            if entry.masks.is_empty() || !entry.masks.iter().all(|m| is_mask(m)) {
                return Err(bad("masks must be four upper-case hex digits".to_string()));
            }
            if entry.category == Category::Likely
                && let Some(mask) = entry.masks.iter().find(|m| !proven_masks.contains(*m))
            {
                return Err(bad(format!(
                    "likely, but family {mask} has no proven device"
                )));
            }
        }
        entries.sort_by(|a, b| a.application_id.cmp(&b.application_id));
        if let Some(pair) = entries
            .windows(2)
            .find(|w| w[0].application_id == w[1].application_id)
        {
            return Err(SupportedListError::Entry {
                index: 0,
                application_id: pair[1].application_id.clone(),
                reason: "listed twice".to_string(),
            });
        }
        list.entries = entries;
        Ok(list)
    }

    /// The list the binary ships, parsed on first use. An embedded file that
    /// does not parse is an empty list (every write then needs the override);
    /// the unit test of this module keeps that from shipping.
    pub fn embedded() -> &'static SupportedList {
        static LIST: OnceLock<SupportedList> = OnceLock::new();
        LIST.get_or_init(|| {
            SupportedList::parse_with(SUPPORTED_DEVICES_TOML, Some(SUPPORTED_GENERATED_TOML))
                .unwrap_or_default()
        })
    }

    /// The entry for `application_id` (case-insensitive), if listed.
    pub fn lookup(&self, application_id: &str) -> Option<&SupportedEntry> {
        let id = application_id.to_ascii_uppercase();
        self.entries
            .binary_search_by(|e| e.application_id.as_str().cmp(id.as_str()))
            .ok()
            .and_then(|i| self.entries.get(i))
    }

    /// Every entry, sorted by application id.
    pub fn entries(&self) -> &[SupportedEntry] {
        &self.entries
    }

    /// The generator's rules.
    pub fn rules(&self) -> &[SupportRule] {
        &self.rules
    }

    /// The families the generator saw.
    pub fn families(&self) -> &[SupportFamily] {
        &self.families
    }

    /// Where the generated half comes from.
    pub fn source(&self) -> &SupportSource {
        &self.source
    }

    /// How many entries of `category` the list holds whose mask passes
    /// `mask`.
    fn count(&self, category: Category, mask: impl Fn(&str) -> bool) -> usize {
        self.entries
            .iter()
            .filter(|e| e.category == category && e.masks.iter().any(|m| mask(m)))
            .count()
    }

    /// The Markdown `docs/explanation/device-support.md` carries between its
    /// `supported-table` markers: the counts per family and per manufacturer,
    /// and every hand-kept entry. The full list is `bussard device
    /// --supported`.
    pub fn markdown_table(&self) -> String {
        let mut out = format!(
            "Sweep manifest of {}, coverage floor {:.1} %.\n\n\
             | Family (mask) | Proven | Likely | Identical, no proven device | Known problems | \
             Synthetic products |\n|---|---|---|---|---|---|\n",
            self.source.sweep_generated.get(..10).unwrap_or("?"),
            self.source.coverage_floor
        );
        let mut masks: BTreeSet<&str> = self
            .entries
            .iter()
            .flat_map(|e| e.masks.iter().map(String::as_str))
            .collect();
        masks.extend(self.families.iter().map(|f| f.mask.as_str()));
        for mask in masks {
            let family = self.families.iter().find(|f| f.mask == mask);
            out.push_str(&format!(
                "| `{mask}` | {} | {} | {} | {} | {} |\n",
                self.count(Category::Proven, |m| m == mask),
                self.count(Category::Likely, |m| m == mask),
                family.map_or(0, |f| f.blocked),
                self.count(Category::Unsupported, |m| m == mask),
                family.map_or(0, |f| f.synthetic),
            ));
        }
        out.push_str(&format!(
            "| all | {} | {} | {} | {} | {} |\n\n",
            self.count(Category::Proven, |_| true),
            self.count(Category::Likely, |_| true),
            self.families.iter().map(|f| f.blocked).sum::<u32>(),
            self.count(Category::Unsupported, |_| true),
            self.families.iter().map(|f| f.synthetic).sum::<u32>(),
        ));
        let mut per_maker: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
        for e in &self.entries {
            let row = per_maker
                .entry(e.application_id.get(..4).unwrap_or("?"))
                .or_default();
            let slot = match e.category {
                Category::Proven => &mut row[0],
                Category::Likely => &mut row[1],
                Category::Unsupported => &mut row[2],
            };
            *slot += 1;
        }
        out.push_str("| Manufacturer | Proven | Likely | Known problems |\n|---|---|---|---|\n");
        for (maker, [p, l, u]) in per_maker {
            out.push_str(&format!("| `M-{maker}` | {p} | {l} | {u} |\n"));
        }
        out.push_str(
            "\nKept by hand:\n\n| Application | Id | Product | Mask | Category | Evidence |\n\
             |---|---|---|---|---|---|\n",
        );
        for e in self.entries.iter().filter(|e| e.source.is_some()) {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | `{}` | {} | {} |\n",
                e.application(),
                e.application_id,
                e.name,
                e.masks.join("`, `"),
                e.category,
                e.evidence
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const PROVEN: &str = "[[device]]\napplication_id = \"0004D14221\"\nname = \"Jung F50\"\n\
                          category = \"proven\"\nevidence = \"live\"\nmask = \"07B0\"\n\
                          source = \"#89\"\n";

    const GENERATED: &str = "[source]\nsweep_manifest = \"m.json\"\n\
         sweep_generated = \"2026-11-10\"\nsynthetic_manifest = \"s.json\"\ncoverage_floor = 95.0\n\
         [[family]]\nmask = \"07B0\"\nblocked = 0\nsynthetic = 3\n\
         [[rule]]\nid = \"sweep-1\"\nchecked = [\"a\"]\nnot_checked = [\"b\"]\nlikely = [\n\
         { id = \"000120DE22\", name = \"Siemens\", masks = [\"07B0\"], coverage = 97.7, \
         uncompared = 1 },\n]\n\
         [differs]\nreason = \"differs from ETS in the sweep\"\nentries = [\n\
         { id = \"000920AA10\", name = \"Hager\", masks = [\"07B0\"], issue = 971, cause = \"c\" },\n]\n";

    fn entry(id: &str, category: &str, evidence: &str, mask: &str, source: &str) -> String {
        format!(
            "[[device]]\napplication_id = \"{id}\"\nname = \"x\"\ncategory = \"{category}\"\n\
             evidence = \"{evidence}\"\nmask = \"{mask}\"\nsource = \"{source}\"\n"
        )
    }

    fn parses(text: &str) -> bool {
        SupportedList::parse(text).is_ok()
    }

    #[test]
    fn test_embedded_list_parses_with_both_halves() -> TestResult {
        // Parsed once, on the first verdict, never by a command that does not
        // ask for one: 1.7 to 2.0 ms in a release build, 14 to 28 ms in a
        // debug build (measured 2026-11-12, both halves, 127 KB).
        let list =
            SupportedList::parse_with(SUPPORTED_DEVICES_TOML, Some(SUPPORTED_GENERATED_TOML))?;
        assert_eq!(SupportedList::embedded(), &list);
        assert!(list.count(Category::Proven, |_| true) >= 4);
        assert!(list.count(Category::Likely, |_| true) > 1000);
        for entry in list.entries() {
            match (entry.evidence, entry.category) {
                (Evidence::Sweep, Category::Likely) => {
                    assert!(entry.rule.is_some() && entry.coverage.is_some());
                }
                (Evidence::Sweep, _) => assert!(entry.issue.is_some() && entry.cause.is_some()),
                _ => assert!(entry.source.is_some()),
            }
        }
        assert!(!list.rules().is_empty());
        assert!(list.rules().iter().all(|r| !r.not_checked.is_empty()));
        Ok(())
    }

    #[test]
    fn test_lookup_finds_by_id_case_insensitive() -> TestResult {
        let list = SupportedList::parse(PROVEN)?;
        let entry = list.lookup("0004d14221").ok_or("not found")?;
        assert_eq!(entry.category, Category::Proven);
        assert_eq!(entry.evidence, Evidence::Live);
        assert_eq!(entry.masks, ["07B0"]);
        assert_eq!(entry.application(), "M-0004_A-D142-21");
        assert!(list.lookup("0083012010").is_none());
        Ok(())
    }

    #[test]
    fn test_parse_refuses_bad_id_mask_duplicate_and_unknown_category() {
        assert!(!parses(&entry(
            "M-0004_A-20DE",
            "proven",
            "live",
            "07B0",
            "#1"
        )));
        assert!(!parses(&entry(
            "000420de22",
            "proven",
            "live",
            "07B0",
            "#1"
        )));
        assert!(!parses(&entry("000420DE22", "guess", "live", "07B0", "#1")));
        assert!(!parses(&entry(
            "000420DE22",
            "proven",
            "capture",
            "07B0",
            "#1"
        )));
        assert!(!parses(&entry("000420DE22", "proven", "live", "7B0", "#1")));
        let twice = format!(
            "{}{}",
            entry("000420DE22", "proven", "live", "07B0", "#1"),
            entry("000420DE22", "proven", "live", "07B0", "#2")
        );
        assert!(!parses(&twice));
    }

    #[test]
    fn test_parse_requires_a_citation() {
        assert!(!parses(&entry(
            "000420DE22",
            "proven",
            "live",
            "07B0",
            "flashed"
        )));
        assert!(parses(&entry(
            "000420DE22",
            "proven",
            "live",
            "07B0",
            "owner 2026-11-12"
        )));
        let uncited = format!(
            "{}mask_source = \"the label\"\n",
            entry("000420DE22", "proven", "live", "07B0", "#1")
        );
        assert!(!parses(&uncited));
        let cited = format!(
            "{}mask_source = \"#89 scan\"\nsweep_differs = \"#1060 capture unusable\"\n",
            entry("000420DE22", "proven", "live", "07B0", "#1")
        );
        assert!(parses(&cited));
    }

    #[test]
    fn test_parse_refuses_every_other_category_and_evidence_pair() {
        // Allowed by hand: proven/live, likely/house-capture,
        // unsupported/issue (with issue and reason).
        let problem = |e: &str| {
            format!(
                "{PROVEN}{}issue = 1\nreason = \"r\"\n",
                entry("000420DE22", "unsupported", e, "07B0", "#1")
            )
        };
        assert!(parses(&problem("issue")));
        for evidence in ["live", "house-capture", "sweep"] {
            assert!(!parses(&problem(evidence)), "unsupported/{evidence}");
        }
        for evidence in ["live", "issue", "sweep"] {
            let likely = format!(
                "{PROVEN}{}",
                entry("000420DE22", "likely", evidence, "07B0", "#1")
            );
            assert!(!parses(&likely), "likely/{evidence}");
        }
        for evidence in ["house-capture", "issue", "sweep"] {
            assert!(
                !parses(&entry("000420DE22", "proven", evidence, "07B0", "#1")),
                "proven/{evidence}"
            );
        }
        // A known problem names its issue and its reason.
        let bare = format!(
            "{PROVEN}{}",
            entry("000420DE22", "unsupported", "issue", "07B0", "#1")
        );
        assert!(!parses(&bare));
        assert!(!parses(&format!("{bare}issue = 1\n")));
        // An entry that passes carries neither.
        let house = entry("000420DE22", "likely", "house-capture", "07B0", "#126");
        assert!(parses(&format!("{PROVEN}{house}")));
        assert!(!parses(&format!("{PROVEN}{house}issue = 1\n")));
        assert!(!parses(&format!("{PROVEN}{house}reason = \"r\"\n")));
    }

    #[test]
    fn test_parse_refuses_likely_without_a_proven_family() -> TestResult {
        let house = entry("000420DE22", "likely", "house-capture", "0701", "#126");
        assert!(!parses(&format!("{PROVEN}{house}")));
        // A generated entry on two masks needs both proven.
        let two = GENERATED.replace(
            "masks = [\"07B0\"], coverage",
            "masks = [\"0705\", \"07B0\"], coverage",
        );
        assert!(SupportedList::parse_with(PROVEN, Some(&two)).is_err());
        let proven_0705 = entry("0004A01113", "proven", "live", "0705", "#89");
        let list = SupportedList::parse_with(&format!("{PROVEN}{proven_0705}"), Some(&two))?;
        let entry = list.lookup("000120DE22").ok_or("missing")?;
        assert_eq!(entry.masks, ["0705", "07B0"]);
        Ok(())
    }

    #[test]
    fn test_parse_with_reads_the_generated_half() -> TestResult {
        let list = SupportedList::parse_with(PROVEN, Some(GENERATED))?;
        let likely = list.lookup("000120DE22").ok_or("likely missing")?;
        assert_eq!(likely.category, Category::Likely);
        assert_eq!(likely.rule.as_deref(), Some("sweep-1"));
        assert_eq!(likely.uncompared, Some(1));
        assert_eq!(likely.problem(), None);
        // The coverage serializes as written, without float noise.
        assert_eq!(
            serde_json::to_value(likely)?["coverage"].to_string(),
            "97.7"
        );
        let differs = list.lookup("000920AA10").ok_or("differs missing")?;
        assert_eq!(differs.category, Category::Unsupported);
        assert_eq!(differs.cause.as_deref(), Some("c"));
        assert_eq!(
            differs.problem().as_deref(),
            Some("differs from ETS in the sweep, #971")
        );
        assert!(
            list.markdown_table()
                .contains("| `07B0` | 1 | 1 | 0 | 1 | 3 |")
        );
        // A generated entry the hand half also lists is refused.
        let both = format!(
            "{PROVEN}{}",
            entry("000120DE22", "likely", "house-capture", "07B0", "#126")
        );
        assert!(SupportedList::parse_with(&both, Some(GENERATED)).is_err());
        Ok(())
    }

    #[test]
    fn test_application_ref_of_formats_the_prefix() {
        assert_eq!(application_ref_of("0002A0ED10"), "M-0002_A-A0ED-10");
        assert_eq!(application_ref_of("short"), "short");
    }
}
