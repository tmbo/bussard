//! TOML parsing with bussard's error rendering and fix-it hints.
//!
//! Every model file goes through here. A parse error keeps the `toml` crate's
//! message and caret and adds a `help:` line where the raw message misleads (the
//! table in `docs/model-format.md`, section Errors). The rules match on the
//! message and on the text around the caret, so they fire for the mistakes
//! people actually make: an unclosed inline table, a YAML-style `-` marker, a
//! bare float where a string belongs, curly quotes pasted from a word
//! processor, and so on.
//!
//! The rendering is the `toml` crate's snippet layout with the file named in
//! the header:
//!
//! ```text
//! TOML parse error in groups.toml at line 1, column 50
//!   |
//! 1 | groups = [{ address = "0/0/1", name = "a", dpt = 1.001 }]
//!   |                                                  ^^^^^
//! invalid type: floating point `1.001`, expected a string
//! help: `dpt` must be a quoted string: `dpt = "1.001"`
//! ```

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

/// A TOML file that could not be parsed or did not match its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The file, as given to the parser (model-relative where possible).
    pub path: PathBuf,
    /// The raw message from the parser (or from bussard's own shape checks).
    pub message: String,
    /// 1-based line of the caret, when the error has a position.
    pub line: Option<usize>,
    /// 1-based column (in characters) of the caret.
    pub column: Option<usize>,
    /// The fix-it hint, when one of the rules matched.
    pub help: Option<String>,
    /// The full rendered text (snippet, message, secondary label, help).
    pub rendered: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rendered)
    }
}

impl std::error::Error for ParseError {}

/// Parses `text` into `T`, rendering any error with its hint.
pub fn parse<T: DeserializeOwned>(path: &Path, text: &str) -> Result<T, ParseError> {
    toml::from_str(text).map_err(|e| error_at(path, text, e.span(), e.message()))
}

/// Parses `text` into a span-carrying `toml_edit` document.
pub fn parse_document(path: &Path, text: &str) -> Result<toml_edit::Document<String>, ParseError> {
    toml_edit::Document::parse(text.to_string())
        .map_err(|e| error_at(path, text, e.span(), e.message()))
}

/// Parses `text` into an editable `toml_edit` document (for format-preserving
/// saves).
pub fn parse_document_mut(path: &Path, text: &str) -> Result<toml_edit::DocumentMut, ParseError> {
    text.parse::<toml_edit::DocumentMut>()
        .map_err(|e| error_at(path, text, e.span(), e.message()))
}

/// Builds a [`ParseError`] for `message` at `span` in `text`, applying the hint
/// rules. Used for the parser's own errors and for bussard's shape checks (a
/// float parameter value, a malformed object entry), so both read alike.
pub fn error_at(path: &Path, text: &str, span: Option<Range<usize>>, message: &str) -> ParseError {
    let span = span.map(|s| clamp_span(text, s));
    let hint = span
        .as_ref()
        .map(|s| hint_for(message, text, s.clone()))
        .unwrap_or_default();
    let mut rendered = String::new();
    let (line, column) = match &span {
        Some(s) => {
            let (line, column) = line_col(text, s.start);
            rendered.push_str(&format!(
                "TOML parse error in {} at line {line}, column {column}\n",
                path.display()
            ));
            rendered.push_str(&snippet(text, s.clone(), '^', None));
            (Some(line), Some(column))
        }
        None => {
            rendered.push_str(&format!("TOML parse error in {}\n", path.display()));
            (None, None)
        }
    };
    rendered.push_str(message.trim_end());
    rendered.push('\n');
    if let Some((secondary, label)) = &hint.secondary {
        rendered.push_str(&snippet(text, secondary.clone(), '-', Some(label)));
    }
    if let Some(help) = &hint.help {
        rendered.push_str("help: ");
        rendered.push_str(help);
        rendered.push('\n');
    }
    ParseError {
        path: path.to_path_buf(),
        message: message.trim_end().to_string(),
        line,
        column,
        help: hint.help,
        rendered,
    }
}

/// Keeps a span inside `text` and on character boundaries.
fn clamp_span(text: &str, span: Range<usize>) -> Range<usize> {
    let mut start = span.start.min(text.len());
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = span.end.clamp(start, text.len());
    while !text.is_char_boundary(end) {
        end += 1;
    }
    start..end
}

/// The 1-based line and character column of byte offset `at`.
pub fn line_col(text: &str, at: usize) -> (usize, usize) {
    let at = at.min(text.len());
    let before = &text[..at];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let column = text[line_start..at].chars().count() + 1;
    (line, column)
}

/// The byte range of the line holding byte offset `at` (without the newline).
fn line_bounds(text: &str, at: usize) -> Range<usize> {
    let at = at.min(text.len());
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    let end = text[at..].find('\n').map_or(text.len(), |i| at + i);
    start..end
}

/// Renders the gutter, the source line and a marker row under `span`.
fn snippet(text: &str, span: Range<usize>, mark: char, label: Option<&str>) -> String {
    let bounds = line_bounds(text, span.start);
    let (line, column) = line_col(text, span.start);
    let source = text[bounds.clone()].trim_end_matches('\r');
    let width = text[span.start..span.end.min(bounds.end)]
        .chars()
        .count()
        .max(1);
    let gutter = " ".repeat(line.to_string().len());
    let mut out = String::new();
    out.push_str(&format!("{gutter} |\n"));
    out.push_str(&format!("{line} | {source}\n"));
    let marks: String = std::iter::repeat_n(mark, width).collect();
    let pad = " ".repeat(column - 1);
    match label {
        Some(label) => out.push_str(&format!("{gutter} | {pad}{marks} {label}\n")),
        None => out.push_str(&format!("{gutter} | {pad}{marks}\n")),
    }
    out
}

/// What a hint rule contributes: a `help:` line and/or a secondary label.
#[derive(Debug, Default)]
struct Hint {
    help: Option<String>,
    secondary: Option<(Range<usize>, String)>,
}

impl Hint {
    fn help(text: impl Into<String>) -> Self {
        Self {
            help: Some(text.into()),
            secondary: None,
        }
    }
}

/// Matches the hint rules against `message` and the text around `span`.
fn hint_for(message: &str, text: &str, span: Range<usize>) -> Hint {
    let line = line_bounds(text, span.start);
    let before_on_line = &text[line.start..span.start];
    let at_caret = &text[span.start..];

    if message.starts_with("duplicate key") {
        return duplicate_key_hint(text, span);
    }
    if message.starts_with("missing comma between array elements")
        && before_on_line.trim_end().ends_with('-')
        && before_on_line.trim() == "-"
    {
        return Hint::help("TOML arrays have no `-` markers; remove the `-`");
    }
    if message.starts_with("missing key for inline table element")
        && let Some(open) = unclosed_brace_line(text, span.start)
    {
        return Hint::help(format!(
            "the entry on line {open} is not closed; add `}}` before the `,`"
        ));
    }
    if (message.starts_with("missing comma between array elements") || message.contains("in array"))
        && let Some((name, open)) = unclosed_array(text, span.start)
    {
        return Hint::help(format!(
            "the array `{name}` opened on line {open} is never closed; add `]`"
        ));
    }
    if (message.starts_with("missing comma between key-value pairs")
        || message.starts_with("unexpected key or value"))
        && before_on_line.ends_with('"')
        && before_on_line.matches('"').count() >= 2
    {
        return Hint::help("escape the quote as `\\\"` or use a literal string `'…'`");
    }
    let bare_word: String = at_caret
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/'))
        .collect();
    if message.starts_with("invalid boolean")
        && !bare_word.is_empty()
        && bare_word != "true"
        && bare_word != "false"
        && let Some(key) = key_before_equals(before_on_line)
    {
        return Hint::help(format!("write `{key} = \"{bare_word}\"`"));
    }
    if message.starts_with("string values must be quoted")
        || message.starts_with("invalid literal string")
    {
        if at_caret.starts_with(['“', '”', '„', '‘', '’']) {
            return Hint::help("“ ” are not quotes in TOML; use straight `\"…\"`");
        }
        if let Some(key) = key_before_equals(before_on_line) {
            let rest = text[span.start..line.end].trim();
            if rest.is_empty() || rest.starts_with('#') {
                return Hint::help(format!(
                    "`{key}` has no value; write `{key} = \"…\"` or remove it"
                ));
            }
            let word = rest.split('#').next().unwrap_or(rest).trim();
            return Hint::help(format!("write `{key} = \"{word}\"`"));
        }
    }
    if message.starts_with("key with no value") && before_on_line.trim_end().ends_with(':') {
        let key = before_on_line.trim().trim_end_matches(':').trim();
        return Hint::help(format!(
            "TOML uses `=`, not `:`; write `{key} = …` (strings in double quotes)"
        ));
    }
    if let Some(rest) = message.strip_prefix("invalid type: ") {
        return invalid_type_hint(rest, text, span, before_on_line);
    }
    if let Some(rest) = message.strip_prefix("unknown field `") {
        return unknown_field_hint(rest);
    }
    Hint::default()
}

/// Hints for serde `invalid type` messages.
fn invalid_type_hint(rest: &str, text: &str, span: Range<usize>, before_on_line: &str) -> Hint {
    let Some(key) = key_before_equals(before_on_line) else {
        return Hint::default();
    };
    let source = text[span.clone()].trim();
    let expected_string = rest.ends_with("expected a string");
    if expected_string
        && (rest.starts_with("floating point")
            || rest.starts_with("integer")
            || rest.starts_with("boolean"))
    {
        return Hint::help(format!(
            "`{key}` must be a quoted string: `{key} = \"{source}\"`"
        ));
    }
    let Some(content) = rest
        .strip_prefix("string \"")
        .and_then(|r| r.split_once("\", expected "))
    else {
        return Hint::default();
    };
    let (value, expected) = content;
    if expected == "a boolean" && (value == "true" || value == "false") {
        return Hint::help(format!("write `{key} = {value}`"));
    }
    if expected == "a sequence" {
        return Hint::help(format!("write `{key} = [\"{value}\"]`"));
    }
    let integer = matches!(
        expected,
        "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64" | "an integer"
    );
    if integer && value.parse::<i64>().is_ok() {
        return Hint::help(format!("write `{key} = {value}`"));
    }
    Hint::default()
}

/// `did you mean` for an unknown field, by edit distance over the expected list.
fn unknown_field_hint(rest: &str) -> Hint {
    let Some((field, tail)) = rest.split_once('`') else {
        return Hint::default();
    };
    let Some(list) = tail.split_once("expected one of ").map(|(_, l)| l) else {
        if let Some(only) = tail
            .split_once("expected `")
            .and_then(|(_, l)| l.split_once('`'))
        {
            return Hint::help(format!("did you mean `{}`?", only.0));
        }
        return Hint::default();
    };
    let candidates: Vec<&str> = list
        .split(',')
        .map(|c| c.trim().trim_matches('`'))
        .filter(|c| !c.is_empty())
        .collect();
    let best = candidates
        .iter()
        .map(|c| (edit_distance(field, c), *c))
        .min_by_key(|(d, c)| (*d, *c));
    match best {
        Some((distance, candidate)) if distance <= (field.chars().count() / 2).max(2) => {
            Hint::help(format!("did you mean `{candidate}`?"))
        }
        _ => Hint::default(),
    }
}

/// Levenshtein distance over characters.
pub(crate) fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The key of the nearest `key =` before the caret on its line.
fn key_before_equals(before_on_line: &str) -> Option<String> {
    let eq = before_on_line.rfind('=')?;
    let head = before_on_line[..eq].trim_end();
    let start = head
        .rfind(|c: char| c == '{' || c == ',' || c.is_whitespace())
        .map_or(0, |i| i + 1);
    let key = head[start..].trim();
    (!key.is_empty()).then(|| key.to_string())
}

/// Walks `text` up to `until` tracking brackets outside strings and comments,
/// calling `on` for every structural `[ ] { }` with its byte offset.
fn scan_brackets(text: &str, until: usize, mut on: impl FnMut(char, usize)) {
    let mut in_string: Option<char> = None;
    let mut in_comment = false;
    let mut escaped = false;
    for (i, c) in text[..until.min(text.len())].char_indices() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
            }
            continue;
        }
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' && quote == '"' {
                escaped = true;
            } else if c == quote || c == '\n' {
                in_string = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => in_string = Some(c),
            '#' => in_comment = true,
            '[' | ']' | '{' | '}' => on(c, i),
            _ => {}
        }
    }
}

/// The 1-based line of the nearest `{` still open at `at` on an earlier line.
fn unclosed_brace_line(text: &str, at: usize) -> Option<usize> {
    let mut stack: Vec<(char, usize)> = Vec::new();
    scan_brackets(text, at, |c, i| match c {
        '[' | '{' => stack.push((c, i)),
        _ => {
            stack.pop();
        }
    });
    let caret_line = line_col(text, at).0;
    stack
        .iter()
        .rev()
        .find(|(c, _)| *c == '{')
        .map(|(_, i)| line_col(text, *i).0)
        .filter(|line| *line < caret_line)
}

/// The name and 1-based line of a value array still open at `at` and opened
/// on an earlier line.
fn unclosed_array(text: &str, at: usize) -> Option<(String, usize)> {
    let mut stack: Vec<(char, usize)> = Vec::new();
    scan_brackets(text, at, |c, i| match c {
        '[' | '{' => stack.push((c, i)),
        _ => {
            stack.pop();
        }
    });
    let caret_line = line_col(text, at).0;
    let (_, open) = stack.iter().find(|(c, _)| *c == '[')?;
    let line = line_col(text, *open).0;
    if line >= caret_line {
        return None;
    }
    let bounds = line_bounds(text, *open);
    let name = key_before_equals(&text[bounds.start..*open])?;
    Some((name, line))
}

/// The secondary `first defined here` label for a duplicate key.
fn duplicate_key_hint(text: &str, span: Range<usize>) -> Hint {
    let key = text[span.clone()].trim();
    let key = key.trim_matches(|c| c == '[' || c == ']').trim();
    if key.is_empty() {
        return Hint::default();
    }
    // The last dotted segment is what collided (`[channel.a-1]` → `a-1`).
    let last = key.rsplit('.').next().unwrap_or(key).trim();
    let mut found = None;
    let mut from = 0;
    while let Some(i) = text[from..span.start].find(last) {
        let at = from + i;
        let end = at + last.len();
        let before_ok = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| c.is_whitespace() || matches!(c, '{' | ',' | '[' | '.' | '"'));
        let after = text[end..].trim_start_matches([' ', '\t', '"']);
        let after_ok = after.starts_with(['=', '.', ']']);
        if before_ok && after_ok {
            found = Some(at..end);
        }
        from = end;
    }
    match found {
        Some(first) => Hint {
            help: None,
            secondary: Some((first, "first defined here".to_string())),
        },
        None => Hint::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_distance_counts_single_edits() {
        assert_eq!(edit_distance("projekt", "project"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("dtp", "dpt"), 2);
    }

    #[test]
    fn test_line_col_counts_characters() {
        let text = "a = \"ü\"\nb = 1\n";
        assert_eq!(line_col(text, 0), (1, 1));
        assert_eq!(line_col(text, text.find('b').unwrap_or(0)), (2, 1));
        assert_eq!(line_col(text, text.find('"').unwrap_or(0) + 3), (1, 7));
    }
}
