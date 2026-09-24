//! Validation rules that need the model files themselves rather than the
//! joined in-memory [`Model`](crate::Model): duplicates the loader collapses,
//! the lock entry a device file depends on, and keys the lock does not know.
//! They report `file:line:column` from the `toml_edit` spans.
//!
//! * **E020** — a group address defined twice in `groups.toml` (reported on
//!   both lines), or one com object named twice in a device file.
//! * **E021** — a device file with channels, parameters or keyed objects but no
//!   `bussard.lock` entry to resolve them.
//! * **E022** — a device file's `product` differs from its lock entry (or the
//!   entry is missing).
//! * **E023** — a key in a device file that the lock does not assign: an
//!   unknown channel, parameter or object key. The message lists the keys the
//!   lock does assign in that table.

use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::Path;

use crate::address::IndividualAddress;
use crate::files::{
    DeviceFileTop, EntryValue, LockDevice, LockFile, Resolver, TableRef, scope_entries,
};
use crate::loader::{DEVICES_DIR, GROUPS_FILE, LOCK_FILE};
use crate::toml_io::{self, line_col};
use crate::validate::{Diagnostic, Severity};

/// `file:line:column` for a span.
fn at(file: &str, text: &str, span: Option<&Range<usize>>) -> String {
    match span {
        Some(s) => {
            let (line, col) = line_col(text, s.start);
            format!("{file}:{line}:{col}")
        }
        None => file.to_string(),
    }
}

/// Runs the file-level rules over the model directory `dir`.
///
/// Files that fail to parse are skipped here: loading the model reports them.
pub fn check_dir(dir: &Path) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    if let Ok(text) = fs::read_to_string(dir.join(GROUPS_FILE)) {
        check_groups(&text, &mut diags);
    }
    let lock: LockFile = fs::read_to_string(dir.join(LOCK_FILE))
        .ok()
        .and_then(|t| toml_io::parse(Path::new(LOCK_FILE), &t).ok())
        .unwrap_or_default();
    let locks: BTreeMap<IndividualAddress, &LockDevice> =
        lock.devices.iter().map(|d| (d.address, d)).collect();
    let devices = dir.join(DEVICES_DIR);
    let mut names: Vec<String> = fs::read_dir(&devices)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| n.ends_with(".toml") && !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    for name in names {
        if let Ok(text) = fs::read_to_string(devices.join(&name)) {
            check_device(&format!("{DEVICES_DIR}/{name}"), &text, &locks, &mut diags);
        }
    }
    diags
}

/// E020 over `groups.toml`.
fn check_groups(text: &str, diags: &mut Vec<Diagnostic>) {
    let Ok(doc) = toml_io::parse_document(Path::new(GROUPS_FILE), text) else {
        return;
    };
    let Some(array) = doc.get("groups").and_then(toml_edit::Item::as_array) else {
        return;
    };
    let mut seen: BTreeMap<String, Vec<Option<Range<usize>>>> = BTreeMap::new();
    for value in array.iter() {
        let Some(table) = value.as_inline_table() else {
            continue;
        };
        let Some(address) = table.get("address").and_then(|v| v.as_str()) else {
            continue;
        };
        let canonical = address
            .parse::<crate::address::GroupAddress>()
            .map(|g| g.to_string())
            .unwrap_or_else(|_| address.to_string());
        seen.entry(canonical).or_default().push(value.span());
    }
    for (address, spans) in seen {
        if spans.len() < 2 {
            continue;
        }
        let lines: Vec<String> = spans
            .iter()
            .map(|s| {
                s.as_ref()
                    .map_or(0, |s| line_col(text, s.start).0)
                    .to_string()
            })
            .collect();
        for span in &spans {
            diags.push(Diagnostic::new(
                "E020",
                Severity::Error,
                at(GROUPS_FILE, text, span.as_ref()),
                format!(
                    "group address {address} is defined {} times (lines {}); keep one entry",
                    spans.len(),
                    lines.join(", ")
                ),
            ));
        }
    }
}

/// E020 (objects), E021, E022 and E023 over one device file.
fn check_device(
    file: &str,
    text: &str,
    locks: &BTreeMap<IndividualAddress, &LockDevice>,
    diags: &mut Vec<Diagnostic>,
) {
    let path = Path::new(file);
    let Ok(top) = toml_io::parse::<DeviceFileTop>(path, text) else {
        return;
    };
    let Ok(doc) = toml_io::parse_document(path, text) else {
        return;
    };
    let Ok(entries) = scope_entries(path, text, &doc) else {
        return;
    };
    let address = top.address;
    let lock = locks.get(&address).copied();
    let product_span = doc
        .as_table()
        .get_key_value("product")
        .and_then(|(k, _)| k.span());
    let address_span = doc
        .as_table()
        .get_key_value("address")
        .and_then(|(k, _)| k.span());

    // E022: the product the lock was generated for.
    match lock {
        Some(l) if l.product != top.product => diags.push(Diagnostic::new(
            "E022",
            Severity::Error,
            at(file, text, product_span.as_ref().or(address_span.as_ref())),
            format!(
                "device {address} is product {} but bussard.lock was generated for {}; run \
                 `bussard import` (or `bussard adopt {address}`) to refresh the lock",
                top.product.as_deref().unwrap_or("(none)"),
                l.product.as_deref().unwrap_or("(none)")
            ),
        )),
        None if top.product.is_some() => diags.push(Diagnostic::new(
            "E022",
            Severity::Error,
            at(file, text, product_span.as_ref()),
            format!(
                "device {address} names product {} but bussard.lock has no entry for it; run \
                 `bussard adopt {address}`, or `bussard import-product` plus `bussard import`",
                top.product.as_deref().unwrap_or_default()
            ),
        )),
        _ => {}
    }

    // E021: something to resolve, but nothing to resolve it with.
    if lock.is_none() {
        let first = entries
            .channels
            .iter()
            .filter_map(|(_, _, s)| s.clone())
            .chain(
                entries
                    .entries
                    .iter()
                    .filter(|e| match &e.value {
                        EntryValue::Param(_) => true,
                        EntryValue::Object { .. } => e.key.parse::<u16>().is_err(),
                    })
                    .filter_map(|e| e.span.clone()),
            )
            .min_by_key(|s| s.start);
        if let Some(span) = first {
            diags.push(Diagnostic::new(
                "E021",
                Severity::Error,
                at(file, text, Some(&span)),
                format!(
                    "device {address} has channels, parameters or keyed objects but no entry in \
                     bussard.lock to resolve them; run `bussard adopt {address}`, `bussard \
                     import <project>`, or `bussard import-product` plus `bussard import`"
                ),
            ));
        }
        return;
    }

    let resolver = Resolver::new(lock);
    let handles: Vec<String> = lock
        .map(|l| l.channels.iter().map(|c| c.handle().to_string()).collect())
        .unwrap_or_default();

    // E023: channels the lock does not define.
    for (handle, _, span) in &entries.channels {
        if !handles.contains(handle) {
            diags.push(Diagnostic::new(
                "E023",
                Severity::Error,
                at(file, text, span.as_ref()),
                format!(
                    "unknown channel `{handle}` on {address}; bussard.lock defines: {}",
                    listing(&handles)
                ),
            ));
        }
    }

    // E023 (keys) and E020 (objects named twice).
    let mut objects: BTreeMap<u16, Vec<Option<Range<usize>>>> = BTreeMap::new();
    for entry in &entries.entries {
        let scope = entry.table.scope();
        match &entry.value {
            EntryValue::Param(_) => {
                let key = entry.full_key();
                if !key.contains('@') && !resolver.knows_param(scope, &key) {
                    diags.push(unknown_key(
                        file,
                        text,
                        entry.span.as_ref(),
                        &entry.table,
                        &key,
                        &resolver,
                        "parameter",
                    ));
                }
            }
            EntryValue::Object { .. } => match resolver.object(scope, &entry.key) {
                Some(n) => objects.entry(n).or_default().push(entry.span.clone()),
                None => diags.push(unknown_key(
                    file,
                    text,
                    entry.span.as_ref(),
                    &entry.table,
                    &entry.key,
                    &resolver,
                    "object",
                )),
            },
        }
    }
    for (number, spans) in objects {
        if spans.len() < 2 {
            continue;
        }
        let lines: Vec<String> = spans
            .iter()
            .map(|s| {
                s.as_ref()
                    .map_or(0, |s| line_col(text, s.start).0)
                    .to_string()
            })
            .collect();
        for span in &spans {
            diags.push(Diagnostic::new(
                "E020",
                Severity::Error,
                at(file, text, span.as_ref()),
                format!(
                    "object {number} on {address} is named {} times (lines {}); keep one entry",
                    spans.len(),
                    lines.join(", ")
                ),
            ));
        }
    }
}

/// The E023 diagnostic for one unknown key.
fn unknown_key(
    file: &str,
    text: &str,
    span: Option<&Range<usize>>,
    table: &TableRef,
    key: &str,
    resolver: &Resolver,
    what: &str,
) -> Diagnostic {
    let keys = resolver.keys_in(table.scope());
    Diagnostic::new(
        "E023",
        Severity::Error,
        at(file, text, span),
        format!(
            "unknown {what} key `{key}` in {}; bussard.lock assigns: {}",
            table.label(),
            listing(&keys)
        ),
    )
}

/// A short comma-separated listing (the first 20 keys).
fn listing(keys: &[String]) -> String {
    if keys.is_empty() {
        return "(none)".to_string();
    }
    let mut shown: Vec<String> = keys.iter().take(20).map(|k| format!("`{k}`")).collect();
    if keys.len() > 20 {
        shown.push(format!("… {} more", keys.len() - 20));
    }
    shown.join(", ")
}
