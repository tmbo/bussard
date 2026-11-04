//! How `plan` and `apply` show a device plan (issue #792): the sentences of
//! [`bussard_download::DevicePlan`], laid out as its `render_text`, with the
//! marks coloured (`+` green, `-` red, `~` yellow), the heading bold and the
//! bookkeeping lines dim. Wording follows `dev/glossary.md`.

use bussard_download::{ChangeMark, DevicePlan};

use crate::style::Style;

/// The plan as text, one line per change, grouped by channel.
pub(crate) fn render(plan: &DevicePlan, style: Style) -> String {
    let mut out = String::new();
    let notes = |out: &mut String| {
        for note in &plan.notes {
            out.push_str(&format!("  {}\n", style.warn(&format!("note: {note}"))));
        }
    };
    if plan.is_empty() {
        out.push_str(&style.ok(&format!(
            "{} matches your project; nothing to write",
            plan.address
        )));
        out.push('\n');
        notes(&mut out);
        return out;
    }
    let heading = if plan.name.trim().is_empty() {
        plan.address.clone()
    } else {
        format!("{} {}", plan.address, plan.name.trim())
    };
    out.push_str(&style.bold(&heading));
    out.push('\n');
    let mut current: Option<Option<&str>> = None;
    for change in &plan.changes {
        let channel = change.channel.as_deref();
        if current != Some(channel) {
            if let Some(handle) = channel {
                let label = match plan.channels.get(handle).map(|n| n.trim()) {
                    Some(name) if !name.is_empty() && name != handle => {
                        format!("channel {handle} ({name})")
                    }
                    _ => format!("channel {handle}"),
                };
                out.push_str(&format!("  {}\n", style.bold(&label)));
            }
            current = Some(channel);
        }
        let indent = if channel.is_some() { "    " } else { "  " };
        let mark = change.mark.symbol().to_string();
        let mark = match change.mark {
            ChangeMark::Added => style.ok(&mark),
            ChangeMark::Removed => style.paint(&mark, crate::style::Tone::Error),
            ChangeMark::Changed => style.warn(&mark),
        };
        out.push_str(&format!("{indent}{mark} {}\n", change.sentence));
    }
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let objects = plural(plan.unchanged_objects, "object");
    let unchanged = match plan.unchanged_parameters {
        Some(p) => Some(format!("{objects}, {}", plural(p, "parameter"))),
        // An interface plan (issue #391) compares no objects.
        None if plan.unchanged_objects == 0 && !plan.writes.interface_properties.is_empty() => None,
        None => Some(objects),
    };
    if let Some(unchanged) = unchanged {
        out.push_str(&format!("  {} {unchanged}\n", style.dim("unchanged:")));
    }
    out.push_str(&format!(
        "  {} {}\n",
        style.dim("writes:"),
        plan.writes.describe()
    ));
    out.push_str(&format!(
        "  {} {}\n",
        style.dim("backup:"),
        style.dim(&plan.backup_dir)
    ));
    notes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_download::{ChangeSubject, PlanChange};

    fn plan() -> DevicePlan {
        DevicePlan {
            address: "1.1.47".to_string(),
            name: "Jalousieaktor".to_string(),
            changes: vec![
                PlanChange {
                    mark: ChangeMark::Added,
                    subject: ChangeSubject::Object,
                    channel: Some("a-1".to_string()),
                    key: "lang".to_string(),
                    object: Some(1),
                    sentence: "lang now listens on 0/1/3".to_string(),
                },
                PlanChange {
                    mark: ChangeMark::Changed,
                    subject: ChangeSubject::Parameter,
                    channel: None,
                    key: "betriebsart".to_string(),
                    object: None,
                    sentence: "betriebsart = Jalousie, was Rollladen".to_string(),
                },
            ],
            channels: [("a-1".to_string(), "Fenster Süd".to_string())].into(),
            unchanged_objects: 3,
            unchanged_parameters: Some(41),
            backup_dir: "captures/backups/".to_string(),
            ..empty("1.1.47")
        }
    }

    fn empty(address: &str) -> DevicePlan {
        DevicePlan {
            address: address.to_string(),
            name: String::new(),
            gateway: String::new(),
            changes: Vec::new(),
            channels: Default::default(),
            unchanged_objects: 0,
            unchanged_parameters: None,
            writes: Default::default(),
            backup_dir: String::new(),
            notes: Vec::new(),
            state_hash: String::new(),
        }
    }

    #[test]
    fn test_render_plain_matches_the_shared_layout() {
        let plan = plan();
        let text = render(&plan, Style::plain());
        assert!(
            text.starts_with(
                "1.1.47 Jalousieaktor\n  channel a-1 (Fenster Süd)\n    + lang now listens on \
                 0/1/3\n  ~ betriebsart = Jalousie, was Rollladen\n  unchanged: 3 objects, 41 \
                 parameters\n  writes: "
            ),
            "{text}"
        );
        assert!(text.ends_with("  backup: captures/backups/\n"), "{text}");
    }

    #[test]
    fn test_render_colours_the_marks() {
        let text = render(&plan(), Style::rich());
        assert!(text.contains("\u{1b}[32m+"), "{text:?}");
        assert!(text.contains("\u{1b}[33m~"), "{text:?}");
    }

    #[test]
    fn test_render_empty_plan_says_your_project() {
        let plan = empty("1.1.4");
        assert_eq!(
            render(&plan, Style::plain()),
            "1.1.4 matches your project; nothing to write\n"
        );
    }
}
