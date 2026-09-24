//! The parse-error hint layer (docs/model-format.md, Errors): each case is a
//! TOML input with a typical mistake and the exact rendered error, caret,
//! message and `help:` line included.

use std::collections::BTreeMap;

use bussard_model::Model;

/// Loads a one-file model and returns the rendered error.
fn render(file: &str, text: &str) -> String {
    let mut files = BTreeMap::new();
    files.insert(file.to_string(), text.to_string());
    match Model::from_texts(&files) {
        Ok(_) => "<loaded without error>".to_string(),
        Err(e) => e.to_string(),
    }
}

/// The cases, as `(name, file, input)`.
const CASES: &[(&str, &str, &str)] = &[
    (
        "unclosed_inline_table",
        "groups.toml",
        "groups = [\n  { address = \"0/0/1\", name = \"a\",\n  { address = \"0/0/2\", name = \"b\" },\n]\n",
    ),
    (
        "unclosed_inline_table_in_ranges",
        "groups.toml",
        "ranges = [\n  { address = \"0\", name = \"UG\"\n  { address = \"1\", name = \"EG\" },\n]\n",
    ),
    (
        "unclosed_array_before_key",
        "groups.toml",
        "groups = [\n  { address = \"0/0/1\", name = \"a\" },\n\nproject = \"x\"\n",
    ),
    (
        "unclosed_array_before_entry",
        "groups.toml",
        "ranges = [\n  { address = \"0\", name = \"UG\" },\n\ngroups = [\n  { address = \"0/0/1\", name = \"a\" },\n]\n",
    ),
    (
        "inner_quote_top_level",
        "groups.toml",
        "project = \"Haus \"Mitte\" Nord\"\n",
    ),
    (
        "inner_quote_inline_table",
        "groups.toml",
        "groups = [\n  { address = \"0/0/1\", name = \"Licht \"Büro\" aussen\" },\n]\n",
    ),
    (
        "key_without_value",
        "bussard.toml",
        "[connection]\ntransport = \"tunnel\"\ngateway = \n",
    ),
    (
        "key_without_value_comment",
        "groups.toml",
        "project = # todo\n",
    ),
    (
        "yaml_dash_marker",
        "groups.toml",
        "groups = [\n  - { address = \"0/0/1\", name = \"a\" },\n]\n",
    ),
    ("curly_quotes", "groups.toml", "project = “Haus”\n"),
    (
        "low_curly_quote",
        "devices/1.1.4.toml",
        "address = \"1.1.4\"\nname = „Aktor“\n",
    ),
    (
        "duplicate_top_level_key",
        "groups.toml",
        "project = \"a\"\nproject = \"b\"\n",
    ),
    (
        "duplicate_table",
        "bussard.toml",
        "[connection]\ntransport = \"tunnel\"\n\n[connection]\ngateway = \"10.0.0.1:3671\"\n",
    ),
    (
        "duplicate_key_in_channel",
        "devices/1.1.4.toml",
        "address = \"1.1.4\"\nname = \"Aktor\"\n\n[channel.a-1]\nname = \"Fenster\"\nname = \"Tür\"\n",
    ),
    (
        "float_dpt",
        "groups.toml",
        "groups = [\n  { address = \"0/0/1\", name = \"a\", dpt = 1.001 },\n]\n",
    ),
    (
        "float_parameter",
        "devices/1.1.4.toml",
        "address = \"1.1.4\"\nname = \"Aktor\"\n\n[parameters]\n\"zeit@P-1_R-1\" = 1.10\n",
    ),
    (
        "integer_address",
        "groups.toml",
        "groups = [\n  { address = 1, name = \"a\" },\n]\n",
    ),
    (
        "string_bool",
        "groups.toml",
        "groups = [\n  { address = \"0/0/1\", name = \"a\", protected = \"true\" },\n]\n",
    ),
    (
        "string_listen",
        "devices/1.1.4.toml",
        "address = \"1.1.4\"\nname = \"Aktor\"\n\n[links]\n12.listen = \"0/1/4\"\n",
    ),
    (
        "string_integer",
        "bussard.toml",
        "[lint.topology]\nmax_devices_per_line = \"21\"\n",
    ),
    (
        "unknown_field_typo",
        "groups.toml",
        "groups = [\n  { address = \"0/0/1\", name = \"a\", dtp = \"1.001\" },\n]\n",
    ),
    (
        "unknown_field_connection",
        "bussard.toml",
        "[connection]\ntransport = \"tunnel\"\ngatway = \"10.0.0.1:3671\"\n",
    ),
    ("yaml_colon", "groups.toml", "project: Haus\n"),
    (
        "bare_word_value",
        "bussard.toml",
        "[connection]\ntransport = tunnel\n",
    ),
];

/// Looks a case up by name.
fn case(name: &str) -> (&'static str, &'static str) {
    CASES
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, f, t)| (*f, *t))
        .unwrap_or(("groups.toml", ""))
}

#[test]
fn test_hint_unclosed_inline_table() {
    let (file, input) = case("unclosed_inline_table");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 3, column 3
  |
3 |   { address = "0/0/2", name = "b" },
  |   ^
missing key for inline table element, expected key
help: the entry on line 2 is not closed; add `}` before the `,`
"##
    );
}

#[test]
fn test_hint_unclosed_inline_table_in_ranges() {
    let (file, input) = case("unclosed_inline_table_in_ranges");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 3, column 3
  |
3 |   { address = "1", name = "EG" },
  |   ^
missing key for inline table element, expected `,`
help: the entry on line 2 is not closed; add `}` before the `,`
"##
    );
}

#[test]
fn test_hint_unclosed_array_before_key() {
    let (file, input) = case("unclosed_array_before_key");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 4, column 9
  |
4 | project = "x"
  |         ^
unexpected `=` in array, expected value, `]`
help: the array `groups` opened on line 1 is never closed; add `]`
"##
    );
}

#[test]
fn test_hint_unclosed_array_before_entry() {
    let (file, input) = case("unclosed_array_before_entry");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 4, column 8
  |
4 | groups = [
  |        ^
unexpected `=` in array, expected value, `]`
help: the array `ranges` opened on line 1 is never closed; add `]`
"##
    );
}

#[test]
fn test_hint_inner_quote_top_level() {
    let (file, input) = case("inner_quote_top_level");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 1, column 18
  |
1 | project = "Haus "Mitte" Nord"
  |                  ^
unexpected key or value, expected newline, `#`
help: escape the quote as `\"` or use a literal string `'…'`
"##
    );
}

#[test]
fn test_hint_inner_quote_inline_table() {
    let (file, input) = case("inner_quote_inline_table");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 2, column 39
  |
2 |   { address = "0/0/1", name = "Licht "Büro" aussen" },
  |                                       ^
missing comma between key-value pairs, expected `,`
help: escape the quote as `\"` or use a literal string `'…'`
"##
    );
}

#[test]
fn test_hint_key_without_value() {
    let (file, input) = case("key_without_value");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in bussard.toml at line 3, column 11
  |
3 | gateway = 
  |           ^
string values must be quoted, expected literal string
help: `gateway` has no value; write `gateway = "…"` or remove it
"##
    );
}

#[test]
fn test_hint_key_without_value_comment() {
    let (file, input) = case("key_without_value_comment");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 1, column 11
  |
1 | project = # todo
  |           ^
string values must be quoted, expected literal string
help: `project` has no value; write `project = "…"` or remove it
"##
    );
}

#[test]
fn test_hint_yaml_dash_marker() {
    let (file, input) = case("yaml_dash_marker");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 2, column 5
  |
2 |   - { address = "0/0/1", name = "a" },
  |     ^
missing comma between array elements, expected `,`
help: TOML arrays have no `-` markers; remove the `-`
"##
    );
}

#[test]
fn test_hint_curly_quotes() {
    let (file, input) = case("curly_quotes");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 1, column 11
  |
1 | project = “Haus”
  |           ^^^^^^
string values must be quoted, expected literal string
help: “ ” are not quotes in TOML; use straight `"…"`
"##
    );
}

#[test]
fn test_hint_low_curly_quote() {
    let (file, input) = case("low_curly_quote");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in devices/1.1.4.toml at line 2, column 8
  |
2 | name = „Aktor“
  |        ^^^^^^^
string values must be quoted, expected literal string
help: “ ” are not quotes in TOML; use straight `"…"`
"##
    );
}

#[test]
fn test_hint_duplicate_top_level_key() {
    let (file, input) = case("duplicate_top_level_key");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 2, column 1
  |
2 | project = "b"
  | ^^^^^^^
duplicate key
  |
1 | project = "a"
  | ------- first defined here
"##
    );
}

#[test]
fn test_hint_duplicate_table() {
    let (file, input) = case("duplicate_table");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in bussard.toml at line 4, column 2
  |
4 | [connection]
  |  ^^^^^^^^^^
duplicate key
  |
1 | [connection]
  |  ---------- first defined here
"##
    );
}

#[test]
fn test_hint_duplicate_key_in_channel() {
    let (file, input) = case("duplicate_key_in_channel");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in devices/1.1.4.toml at line 6, column 1
  |
6 | name = "Tür"
  | ^^^^
duplicate key
  |
5 | name = "Fenster"
  | ---- first defined here
"##
    );
}

#[test]
fn test_hint_float_dpt() {
    let (file, input) = case("float_dpt");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 2, column 42
  |
2 |   { address = "0/0/1", name = "a", dpt = 1.001 },
  |                                          ^^^^^
invalid type: floating point `1.001`, expected a string
help: `dpt` must be a quoted string: `dpt = "1.001"`
"##
    );
}

#[test]
fn test_hint_float_parameter() {
    let (file, input) = case("float_parameter");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in devices/1.1.4.toml at line 5, column 18
  |
5 | "zeit@P-1_R-1" = 1.10
  |                  ^^^^
invalid type: floating point `1.10`, expected a string
help: `"zeit@P-1_R-1"` must be a quoted string: `"zeit@P-1_R-1" = "1.10"`
"##
    );
}

#[test]
fn test_hint_integer_address() {
    let (file, input) = case("integer_address");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 2, column 15
  |
2 |   { address = 1, name = "a" },
  |               ^
invalid type: integer `1`, expected a string
help: `address` must be a quoted string: `address = "1"`
"##
    );
}

#[test]
fn test_hint_string_bool() {
    let (file, input) = case("string_bool");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 2, column 48
  |
2 |   { address = "0/0/1", name = "a", protected = "true" },
  |                                                ^^^^^^
invalid type: string "true", expected a boolean
help: write `protected = true`
"##
    );
}

#[test]
fn test_hint_string_listen() {
    let (file, input) = case("string_listen");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in devices/1.1.4.toml at line 5, column 13
  |
5 | 12.listen = "0/1/4"
  |             ^^^^^^^
invalid type: string "0/1/4", expected a sequence
help: write `12.listen = ["0/1/4"]`
"##
    );
}

#[test]
fn test_hint_string_integer() {
    let (file, input) = case("string_integer");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in bussard.toml at line 2, column 24
  |
2 | max_devices_per_line = "21"
  |                        ^^^^
invalid type: string "21", expected usize
help: write `max_devices_per_line = 21`
"##
    );
}

#[test]
fn test_hint_unknown_field_typo() {
    let (file, input) = case("unknown_field_typo");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 2, column 36
  |
2 |   { address = "0/0/1", name = "a", dtp = "1.001" },
  |                                    ^^^
unknown field `dtp`, expected one of `address`, `name`, `dpt`, `description`, `protected`, `secure`
help: did you mean `dpt`?
"##
    );
}

#[test]
fn test_hint_unknown_field_connection() {
    let (file, input) = case("unknown_field_connection");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in bussard.toml at line 3, column 1
  |
3 | gatway = "10.0.0.1:3671"
  | ^^^^^^
unknown field `gatway`, expected one of `transport`, `gateway`, `multicast`, `keyring`
help: did you mean `gateway`?
"##
    );
}

#[test]
fn test_hint_yaml_colon() {
    let (file, input) = case("yaml_colon");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in groups.toml at line 1, column 10
  |
1 | project: Haus
  |          ^
key with no value, expected `=`
help: TOML uses `=`, not `:`; write `project = …` (strings in double quotes)
"##
    );
}

#[test]
fn test_hint_bare_word_value() {
    let (file, input) = case("bare_word_value");
    assert_eq!(
        render(file, input),
        r##"TOML parse error in bussard
"##
    );
}

#[test]
fn test_every_case_has_a_help_or_secondary_label() {
    for (name, file, input) in CASES {
        let text = render(file, input);
        assert!(
            text.contains("\nhelp: ") || text.contains("first defined here"),
            "{name} renders no hint:\n{text}"
        );
    }
}
