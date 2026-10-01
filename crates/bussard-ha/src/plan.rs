//! What writing the generated YAML would change in the file Home Assistant
//! reads (issue #280).
//!
//! [`classify`] decides whether the file at `home_assistant.config_path` is
//! one bussard may overwrite, and in which [`Layout`]; [`render_for`] shapes
//! the generated text for that layout; [`diff`] compares the entities of two
//! texts and says per entity what is added, changed or removed, one sentence
//! each.
//!
//! Entities are keyed by platform and `name` (an entry without a name by its
//! `entity_id` or `address`), the way Home Assistant's KNX YAML names them.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_norway::Value;

/// The top-level keys of a KNX YAML block: the platforms Home Assistant's KNX
/// integration accepts (and `expose`). A file whose top-level keys are all
/// from this list is the inside of a `knx:` block.
pub const KNX_KEYS: [&str; 21] = [
    "binary_sensor",
    "button",
    "climate",
    "cover",
    "date",
    "datetime",
    "event",
    "expose",
    "fan",
    "light",
    "notify",
    "number",
    "scene",
    "select",
    "sensor",
    "switch",
    "text",
    "time",
    "valve",
    "weather",
    "config_file",
];

/// How the file holds the KNX configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// A package file: one top-level `knx:` key (what `bussard ha-config`
    /// prints).
    Package,
    /// The inside of the block: `configuration.yaml` says
    /// `knx: !include <file>`, so the platforms are the top-level keys.
    Included,
}

/// Whether bussard may overwrite the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FileState {
    /// A KNX YAML file in `layout`: bussard may overwrite it.
    Yaml {
        /// The file's shape, kept when it is rewritten.
        layout: Layout,
        /// Whether the file carries bussard's generated-by header.
        generated_by_bussard: bool,
    },
    /// Not a file bussard overwrites; `reason` says why and what to do.
    NotYaml {
        /// Why, in one sentence with the fix.
        reason: String,
    },
}

impl FileState {
    /// The layout, when bussard may overwrite the file.
    pub fn layout(&self) -> Option<Layout> {
        match self {
            FileState::Yaml { layout, .. } => Some(*layout),
            FileState::NotYaml { .. } => None,
        }
    }
}

/// Classifies the current contents of the configured file (`None`: the file
/// does not exist).
pub fn classify(text: Option<&str>) -> FileState {
    let Some(text) = text else {
        return FileState::NotYaml {
            reason: "the file does not exist. Create it first and include it from Home \
                     Assistant's configuration.yaml: with the single line `knx:` when it is \
                     loaded as a package, or with `{}` when configuration.yaml says \
                     `knx: !include <file>`"
                .to_string(),
        };
    };
    let generated_by_bussard = text.starts_with(crate::emit::HEADER_PREFIX);
    let value: Value = match serde_norway::from_str(text) {
        Ok(v) => v,
        Err(err) => {
            return FileState::NotYaml {
                reason: format!("the file is not valid YAML ({err}); fix or replace it by hand"),
            };
        }
    };
    let Value::Mapping(map) = value else {
        return FileState::NotYaml {
            reason: if matches!(value, Value::Null) {
                "the file is empty, so its shape is unknown. Write the single line `knx:` \
                 into it when Home Assistant loads it as a package, or `{}` when \
                 configuration.yaml says `knx: !include <file>`"
                    .to_string()
            } else {
                "the file is not a YAML mapping".to_string()
            },
        };
    };
    let keys: Vec<String> = map
        .keys()
        .map(|k| k.as_str().map(str::to_string).unwrap_or_else(|| render(k)))
        .collect();
    if keys.len() == 1 && keys[0] == "knx" {
        return FileState::Yaml {
            layout: Layout::Package,
            generated_by_bussard,
        };
    }
    if keys.iter().any(|k| k == "knx") {
        let others: Vec<&str> = keys
            .iter()
            .map(String::as_str)
            .filter(|k| *k != "knx")
            .collect();
        return FileState::NotYaml {
            reason: format!(
                "the file holds more than the knx block (also {}); bussard writes only a \
                 file of its own. Move the knx block to its own package file and point \
                 home_assistant.config_path there",
                others.join(", ")
            ),
        };
    }
    if keys.iter().all(|k| KNX_KEYS.contains(&k.as_str())) {
        return FileState::Yaml {
            layout: Layout::Included,
            generated_by_bussard,
        };
    }
    let unknown: Vec<&str> = keys
        .iter()
        .map(String::as_str)
        .filter(|k| !KNX_KEYS.contains(k))
        .collect();
    FileState::NotYaml {
        reason: format!(
            "the file is not a KNX YAML file (top-level keys {}); point \
             home_assistant.config_path at the file that holds the knx block",
            unknown.join(", ")
        ),
    }
}

/// The generated text shaped for `layout`: unchanged for a package file; for
/// an included file the platforms move to the top level, with the same
/// header and summary footer.
///
/// # Errors
///
/// The YAML error of re-reading or re-writing the generated document.
pub fn render_for(generated: &str, layout: Layout) -> Result<String, serde_norway::Error> {
    if layout == Layout::Package {
        return Ok(generated.to_string());
    }
    let (header, rest) = match generated.split_once('\n') {
        Some((first, rest)) if first.starts_with('#') => (format!("{first}\n"), rest),
        _ => (String::new(), generated),
    };
    let (body, footer) = match rest.find("\n# summary\n") {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, ""),
    };
    let value: Value = serde_norway::from_str(body)?;
    let inner = value.get("knx").cloned().unwrap_or(Value::Null);
    let inner_text = match inner {
        Value::Mapping(ref m) if !m.is_empty() => serde_norway::to_string(&inner)?,
        _ => "{}\n".to_string(),
    };
    Ok(format!("{header}{inner_text}{footer}"))
}

/// One entity of a KNX YAML file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct YamlEntity {
    platform: String,
    name: String,
    /// The entity's keys and values in file order, `name` excluded.
    fields: Vec<(String, String)>,
}

/// One field that differs between the file and the generated text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldChange {
    /// The key, e.g. `state_address`.
    pub key: String,
    /// The value in the file now.
    pub from: Option<String>,
    /// The value after the write.
    pub to: Option<String>,
}

/// What happens to one entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityChangeKind {
    /// New in the generated text.
    Added,
    /// In both, with different fields.
    Changed,
    /// In the file only: the write removes it.
    Removed,
}

/// One entity added, changed or removed, with its sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntityChange {
    /// Added, changed or removed.
    pub kind: EntityChangeKind,
    /// The platform, e.g. `light`.
    pub platform: String,
    /// The entity name.
    pub name: String,
    /// The fields that differ (all fields for an added or removed entity).
    pub fields: Vec<FieldChange>,
    /// One line for the human, e.g. `+ light "Küche" (address 1/0/1)`.
    pub sentence: String,
}

/// The entity diff between the file and the generated text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntityDiff {
    /// Every added, changed or removed entity: removed first, then changed,
    /// then added, each in file order.
    pub changes: Vec<EntityChange>,
    /// Entities identical in both.
    pub unchanged: usize,
    /// Entities in the generated text.
    pub generated: usize,
    /// Entities in the file now.
    pub current: usize,
}

/// An error reading a KNX YAML text.
#[derive(Debug, thiserror::Error)]
#[error("reading the KNX YAML: {0}")]
pub struct PlanError(#[from] serde_norway::Error);

/// The entities of `current` (the file, `None` when missing) against
/// `desired` (the text bussard would write).
///
/// # Errors
///
/// [`PlanError`] when either text is not YAML.
pub fn diff(current: Option<&str>, desired: &str) -> Result<EntityDiff, PlanError> {
    let before = match current {
        Some(text) => entities(text)?,
        None => Vec::new(),
    };
    let after = entities(desired)?;
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut added = Vec::new();
    let mut unchanged = 0;
    for old in &before {
        match after
            .iter()
            .find(|e| e.platform == old.platform && e.name == old.name)
        {
            None => removed.push(change(
                EntityChangeKind::Removed,
                old,
                field_list(old, false),
            )),
            Some(new) if new.fields == old.fields => unchanged += 1,
            Some(new) => changed.push(change(EntityChangeKind::Changed, new, field_diff(old, new))),
        }
    }
    for new in &after {
        if !before
            .iter()
            .any(|e| e.platform == new.platform && e.name == new.name)
        {
            added.push(change(EntityChangeKind::Added, new, field_list(new, true)));
        }
    }
    let mut changes = removed;
    changes.extend(changed);
    changes.extend(added);
    Ok(EntityDiff {
        changes,
        unchanged,
        generated: after.len(),
        current: before.len(),
    })
}

/// The group addresses a KNX YAML text uses: every value of a key that
/// mentions `address`. A text that is not YAML uses none.
pub fn exposed_addresses(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entity in entities(text).unwrap_or_default() {
        for (key, value) in entity.fields {
            if key.contains("address") {
                out.insert(value);
            }
        }
    }
    out
}

/// Every entity in `text`, either layout, in file order. Duplicate names in
/// one platform get a ` #2`, ` #3` suffix so each stays addressable.
fn entities(text: &str) -> Result<Vec<YamlEntity>, PlanError> {
    let value: Value = serde_norway::from_str(text)?;
    let platforms = match value.get("knx") {
        Some(inner) => inner.clone(),
        None => value,
    };
    let mut out: Vec<YamlEntity> = Vec::new();
    let Value::Mapping(map) = platforms else {
        return Ok(out);
    };
    for (platform, list) in &map {
        let platform = platform
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| render(platform));
        let Value::Sequence(items) = list else {
            continue;
        };
        for (index, item) in items.iter().enumerate() {
            let Value::Mapping(fields) = item else {
                continue;
            };
            let mut name = None;
            let mut list = Vec::new();
            for (key, value) in fields {
                let key = key
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| render(key));
                let value = render(value);
                if key == "name" {
                    name = Some(value);
                } else {
                    list.push((key, value));
                }
            }
            let name = name
                .or_else(|| field(&list, "entity_id"))
                .or_else(|| field(&list, "address"))
                .unwrap_or_else(|| format!("#{}", index + 1));
            let mut unique = name.clone();
            let mut n = 1;
            while out
                .iter()
                .any(|e| e.platform == platform && e.name == unique)
            {
                n += 1;
                unique = format!("{name} #{n}");
            }
            out.push(YamlEntity {
                platform: platform.clone(),
                name: unique,
                fields: list,
            });
        }
    }
    Ok(out)
}

fn field(list: &[(String, String)], key: &str) -> Option<String> {
    list.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// A scalar as its text; anything else as compact YAML.
fn render(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => "null".to_string(),
        other => serde_norway::to_string(other)
            .map(|s| s.trim().replace('\n', " "))
            .unwrap_or_default(),
    }
}

/// Every field of `entity`, as added (`to`) or removed (`from`).
fn field_list(entity: &YamlEntity, added: bool) -> Vec<FieldChange> {
    entity
        .fields
        .iter()
        .map(|(key, value)| FieldChange {
            key: key.clone(),
            from: (!added).then(|| value.clone()),
            to: added.then(|| value.clone()),
        })
        .collect()
}

/// The fields that differ between `old` and `new`, in `new`'s order then the
/// dropped ones.
fn field_diff(old: &YamlEntity, new: &YamlEntity) -> Vec<FieldChange> {
    let mut out = Vec::new();
    for (key, value) in &new.fields {
        let before = field(&old.fields, key);
        if before.as_deref() != Some(value.as_str()) {
            out.push(FieldChange {
                key: key.clone(),
                from: before,
                to: Some(value.clone()),
            });
        }
    }
    for (key, value) in &old.fields {
        if field(&new.fields, key).is_none() {
            out.push(FieldChange {
                key: key.clone(),
                from: Some(value.clone()),
                to: None,
            });
        }
    }
    out
}

fn change(kind: EntityChangeKind, entity: &YamlEntity, fields: Vec<FieldChange>) -> EntityChange {
    let head = format!("{} \"{}\"", entity.platform, entity.name);
    let sentence = match kind {
        EntityChangeKind::Added => {
            let parts: Vec<String> = fields
                .iter()
                .map(|f| format!("{} {}", f.key, f.to.as_deref().unwrap_or_default()))
                .collect();
            if parts.is_empty() {
                format!("+ {head}")
            } else {
                format!("+ {head} ({})", parts.join(", "))
            }
        }
        EntityChangeKind::Removed => format!("- {head}"),
        EntityChangeKind::Changed => {
            let parts: Vec<String> = fields
                .iter()
                .map(|f| match (&f.from, &f.to) {
                    (Some(from), Some(to)) => format!("{} {to}, was {from}", f.key),
                    (None, Some(to)) => format!("{} {to} added", f.key),
                    (Some(from), None) => format!("{} removed (was {from})", f.key),
                    (None, None) => f.key.clone(),
                })
                .collect();
            format!("~ {head}: {}", parts.join("; "))
        }
    };
    EntityChange {
        kind,
        platform: entity.platform.clone(),
        name: entity.name.clone(),
        fields,
        sentence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const GENERATED: &str = "# generated by bussard ha-config\nknx:\n  switch:\n  - name: Pumpe\n    address: 1/0/1\n    state_address: 1/0/2\n  light:\n  - name: Küche\n    address: 1/1/1\n\n# summary\n# entities: 1 switch\n";

    #[test]
    fn test_classify_missing_empty_package_included_and_foreign() {
        assert!(matches!(classify(None), FileState::NotYaml { .. }));
        assert!(matches!(classify(Some("")), FileState::NotYaml { .. }));
        assert_eq!(classify(Some("knx:\n")).layout(), Some(Layout::Package));
        assert_eq!(classify(Some("{}\n")).layout(), Some(Layout::Included));
        assert_eq!(
            classify(Some("light:\n- name: A\n  address: 1/1/1\n")).layout(),
            Some(Layout::Included)
        );
        assert!(matches!(
            classify(Some("knx:\nautomation: []\n")),
            FileState::NotYaml { .. }
        ));
        assert!(matches!(
            classify(Some("homeassistant:\n  name: x\n")),
            FileState::NotYaml { .. }
        ));
        assert!(matches!(
            classify(Some("knx: [\n")),
            FileState::NotYaml { .. }
        ));
    }

    #[test]
    fn test_render_for_included_moves_platforms_up() -> TestResult {
        let text = render_for(GENERATED, Layout::Included)?;
        assert!(text.starts_with("# generated by bussard"), "{text}");
        assert!(text.contains("\nswitch:\n"), "{text}");
        assert!(!text.contains("knx:"), "{text}");
        assert!(text.ends_with("# entities: 1 switch\n"), "{text}");
        assert_eq!(classify(Some(&text)).layout(), Some(Layout::Included));
        assert_eq!(diff(Some(GENERATED), &text)?.changes, Vec::new());
        Ok(())
    }

    #[test]
    fn test_diff_reports_added_changed_and_removed() -> TestResult {
        let current = "knx:\n  switch:\n  - name: Pumpe\n    address: 1/0/1\n    state_address: 1/0/9\n  sensor:\n  - name: Alt\n    state_address: 7/7/7\n    type: temperature\n";
        let plan = diff(Some(current), GENERATED)?;
        let sentences: Vec<&str> = plan.changes.iter().map(|c| c.sentence.as_str()).collect();
        assert_eq!(
            sentences,
            [
                "- sensor \"Alt\"",
                "~ switch \"Pumpe\": state_address 1/0/2, was 1/0/9",
                "+ light \"Küche\" (address 1/1/1)",
            ]
        );
        assert_eq!(plan.unchanged, 0);
        assert_eq!((plan.current, plan.generated), (2, 2));
        Ok(())
    }

    #[test]
    fn test_diff_identical_is_empty() -> TestResult {
        let plan = diff(Some(GENERATED), GENERATED)?;
        assert!(plan.changes.is_empty());
        assert_eq!(plan.unchanged, 2);
        Ok(())
    }

    #[test]
    fn test_exposed_addresses_lists_address_values() {
        let gas = exposed_addresses(GENERATED);
        assert!(gas.contains("1/0/2") && gas.contains("1/1/1"), "{gas:?}");
        assert_eq!(gas.len(), 3);
    }
}
