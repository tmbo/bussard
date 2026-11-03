//! Documentation consistency checks (issue #107).
//!
//! - `docs/explanation/device-support.md`'s "Supported device masks" table is rendered from
//!   [`bussard_mgmt::capability_table`], the same source `plan`, `apply`,
//!   `flash`, `reconstruct` and `audit` use, and must match byte-for-byte.
//! - the pages under `docs/reference/commands/` document every long flag any subcommand's `--help`
//!   prints.
//! - `docs/reference/mcp-tools.md` states the tool count of every MCP tier the
//!   built server registers, and names every tool of each tier (issue #704).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bussard_mcp::tier_help::{TierCounts, tier_counts};
use bussard_mcp::{tools_ha, tools_model, tools_program};
use bussard_mgmt::{MaskCapabilities, MaskProfile, PROPERTY_ONLY_FLASH_MASK, capability_table};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Marks the start of the generated table in `docs/explanation/device-support.md`.
const TABLE_START: &str = "<!-- mask-table:start -->";
/// Marks the end of the generated table in `docs/explanation/device-support.md`.
const TABLE_END: &str = "<!-- mask-table:end -->";

fn docs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs")
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// The `flash` cell: `yes`, `no`, or `property-only` for a mask whose
/// property-only load procedures run although the family is not downloaded.
fn flash_cell(caps: &MaskCapabilities) -> &'static str {
    if !caps.flash && caps.flash_property_only {
        "property-only"
    } else {
        yes_no(caps.flash)
    }
}

/// Renders the capability table as the Markdown that lives in device-support.md.
fn render_mask_table() -> String {
    let mut out = String::from(
        "| Mask | Family | Medium | `plan` / `apply` | `flash` | `reconstruct` | `describe` | Notes |\n\
         |---|---|---|---|---|---|---|---|\n",
    );
    for (mask, caps) in capability_table() {
        let profile = MaskProfile::from_mask(mask);
        out.push_str(&format!(
            "| `{mask:04X}` | {} | {} | {} | {} | {} | {} | {} |\n",
            profile.family().label(),
            profile.medium().label(),
            yes_no(caps.plan_apply),
            flash_cell(&caps),
            yes_no(caps.reconstruct),
            yes_no(caps.describe),
            caps.note
        ));
    }
    out
}

#[test]
fn test_safety_mask_table_matches_capability_table() -> TestResult {
    let safety = std::fs::read_to_string(docs().join("explanation/device-support.md"))?;
    let section = safety
        .find("## Supported device masks")
        .ok_or("device-support.md has no \"Supported device masks\" section")?;
    let rest = &safety[section..];
    let start = rest.find(TABLE_START).ok_or("no mask-table start marker")?;
    let end = rest.find(TABLE_END).ok_or("no mask-table end marker")?;
    // The marker line may carry a trailing comment; the table starts on the next line.
    let after_start = &rest[start..end];
    let body = after_start
        .split_once('\n')
        .map(|(_, b)| b)
        .ok_or("empty table block")?;
    let expected = render_mask_table();
    assert_eq!(
        body, expected,
        "docs/explanation/device-support.md's mask table is stale; replace the block between the markers with:\n{expected}"
    );
    Ok(())
}

/// The `0021` row reads `property-only` in the `flash` column, and the prose
/// below the table explains that state.
#[test]
fn test_safety_mask_table_marks_property_only_flash() -> TestResult {
    let doc = std::fs::read_to_string(docs().join("explanation/device-support.md"))?;
    let mask = PROPERTY_ONLY_FLASH_MASK;
    let caps = MaskProfile::from_mask(mask).capabilities();
    assert!(caps.flash_property_only && !caps.flash);
    let row_start = format!("| `{mask:04X}` |");
    let row = doc
        .lines()
        .find(|line| line.starts_with(&row_start))
        .ok_or("device-support.md has no 0021 row")?;
    let cells: Vec<&str> = row.split('|').map(str::trim).collect();
    // cells[0] is empty (before the first pipe); `flash` is the fifth column.
    assert_eq!(cells.get(5).copied(), Some("property-only"), "{row}");
    let end = doc.find(TABLE_END).ok_or("no mask-table end marker")?;
    let after = &doc[end..];
    assert!(
        after.contains("`property-only`") && after.contains(&format!("`{mask:04X}`")),
        "the prose below the mask table must explain `property-only` on `{mask:04X}`"
    );
    Ok(())
}

/// Runs `bussard <args> --help` and returns stdout.
fn help(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .arg("--help")
        .output()?;
    if !out.status.success() {
        return Err(format!("`bussard {} --help` failed", args.join(" ")).into());
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// The subcommand names listed under `Commands:` in the top-level help.
fn subcommands(top: &str) -> Vec<String> {
    top.lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|name| *name != "help")
        .map(str::to_string)
        .collect()
}

/// Every `--long-flag` token in a help text.
fn long_flags(text: &str) -> Vec<String> {
    let mut flags = Vec::new();
    for (i, _) in text.match_indices("--") {
        let tail = &text[i + 2..];
        let name: String = tail
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
            .collect();
        if name.is_empty() || name.starts_with('-') {
            continue;
        }
        // Only flags defined in the option list (start of a help line).
        let line_start = text[..i].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let prefix = text[line_start..i].trim();
        if !prefix.is_empty() && !prefix.ends_with(',') {
            continue;
        }
        flags.push(format!("--{name}"));
    }
    flags.sort();
    flags.dedup();
    flags
}

/// Whether `doc` mentions `flag` as a whole token.
fn mentions(doc: &str, flag: &str) -> bool {
    doc.match_indices(flag).any(|(i, _)| {
        let next = doc[i + flag.len()..].chars().next();
        !matches!(next, Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

/// The text of a command's `## \`bussard <command>...` (or `###`) section in
/// the concatenated reference pages, up to the next heading of the same or a
/// higher level.
fn command_section<'a>(doc: &'a str, command: &str) -> Option<&'a str> {
    for level in ["## ", "### "] {
        let heading = format!("{level}`bussard {command}");
        let found = doc.match_indices(&heading).find_map(|(i, _)| {
            // Only a heading at the start of a line, and the whole command name
            // (`import` must not match `import-product`).
            let at_line_start = i == 0 || doc.as_bytes()[i - 1] == b'\n';
            let next = doc[i + heading.len()..].chars().next();
            (at_line_start && matches!(next, Some(' ' | '`'))).then_some(i)
        });
        let Some(start) = found else { continue };
        let body = &doc[start + heading.len()..];
        let end = if level == "## " {
            body.find("\n## ")
        } else {
            body.find("\n### ").or_else(|| body.find("\n## "))
        }
        .unwrap_or(body.len());
        return Some(&body[..end]);
    }
    None
}

/// Every page under `docs/reference/commands/` plus `global-options.md`
/// (where the global flags are documented once), concatenated.
fn reference_pages() -> Result<String, Box<dyn std::error::Error>> {
    let dir = docs().join("reference/commands");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    names.sort();
    names.push(docs().join("reference/global-options.md"));
    let mut out = String::new();
    for path in names {
        out.push_str(&std::fs::read_to_string(path)?);
        out.push('\n');
    }
    Ok(out)
}

#[test]
fn test_reference_documents_every_help_flag() -> TestResult {
    let reference = reference_pages()?;
    let top = help(&[])?;
    let commands = subcommands(&top);
    assert!(
        commands.len() > 10,
        "parsed too few subcommands: {commands:?}"
    );

    // Global flags appear in every subcommand's help; they are documented once.
    let globals = long_flags(&top);

    let mut missing = Vec::new();
    for command in &commands {
        let Some(section) = command_section(&reference, command) else {
            missing.push(format!("section for `bussard {command}`"));
            continue;
        };
        for flag in long_flags(&help(&[command])?) {
            if flag == "--help" || flag == "--version" {
                continue;
            }
            let documented = if globals.contains(&flag) {
                mentions(&reference, &flag)
            } else {
                mentions(section, &flag)
            };
            if !documented {
                missing.push(format!("`bussard {command} {flag}`"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "docs/reference/commands/ does not document:\n  {}",
        missing.join("\n  ")
    );
    Ok(())
}

#[test]
fn test_long_flags_parses_option_lines_only() {
    let text =
        "Options:\n      --dir <DIR>  The dir (see --other in prose)\n  -v, --verbose  Louder\n";
    assert_eq!(long_flags(text), vec!["--dir", "--verbose"]);
}

/// The "Tool counts" line of `docs/reference/mcp-tools.md`, rendered from the
/// registration tables.
fn render_tool_counts(c: TierCounts) -> String {
    format!(
        "- Tool counts: {} in `--passive`, {} by default, {} with `--allow-writes`. \
         `--no-model-edits` takes {} away from each ({}, {} and {}). \
         `--allow-programming` adds {} to any non-passive tier. \
         The Home Assistant tier adds {} to any tier.",
        c.passive,
        c.default,
        c.writes,
        c.model_edits,
        c.passive - c.model_edits,
        c.default - c.model_edits,
        c.writes - c.model_edits,
        c.programming,
        c.home_assistant
    )
}

/// The row of the tier table in `mcp-tools.md` whose first cell is `tier`.
fn tier_row<'a>(doc: &'a str, tier: &str) -> Result<&'a str, String> {
    let start = format!("| {tier} |");
    doc.lines()
        .find(|line| line.starts_with(&start))
        .ok_or_else(|| format!("mcp-tools.md has no tier row {tier:?}"))
}

#[test]
fn test_mcp_tools_doc_states_the_tier_counts() -> TestResult {
    let doc = std::fs::read_to_string(docs().join("reference/mcp-tools.md"))?;
    let expected = render_tool_counts(tier_counts());
    assert!(
        doc.lines().any(|line| line == expected),
        "docs/reference/mcp-tools.md's tool counts are stale; the line should read:\n{expected}"
    );
    Ok(())
}

#[test]
fn test_mcp_tools_doc_names_every_tier_tool() -> TestResult {
    let doc = std::fs::read_to_string(docs().join("reference/mcp-tools.md"))?;
    let tiers: [(&str, Vec<&str>); 5] = [
        ("Passive", bussard_mcp::tier_help::passive_omitted()),
        ("Write", bussard_mcp::tier_help::writes_added()),
        ("Programming", tools_program::PROGRAMMING_TOOLS.to_vec()),
        ("Home Assistant", tools_ha::HA_TOOLS.to_vec()),
        ("No model edits", tools_model::MODEL_EDIT_TOOLS.to_vec()),
    ];
    for (tier, tools) in tiers {
        let row = tier_row(&doc, tier)?;
        for tool in tools {
            assert!(
                row.contains(&format!("`{tool}`")),
                "mcp-tools.md's {tier} row does not name `{tool}`"
            );
        }
    }
    Ok(())
}

/// Starts the built `bussard mcp` with `flags` on a minimal model against a
/// loopback gateway nobody answers on, and returns the names `tools/list`
/// reports.
fn served_tools(flags: &[&str]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let tmp = std::env::temp_dir().join(format!(
        "bussard-docs-tiers-{}-{}",
        std::process::id(),
        flags.join("")
    ));
    std::fs::create_dir_all(&tmp)?;
    std::fs::write(tmp.join("bussard.toml"), "")?;
    std::fs::write(tmp.join("groups.toml"), "project = \"Demo\"\ngroups = []\n")?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_NO_DOTENV", "1")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .args(["mcp", "--dir"])
        .arg(&tmp)
        .args(["--gateway", "127.0.0.1:9"])
        .args(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let mut reader = BufReader::new(stdout);
    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "docs", "version": "0"}
        }
    });
    writeln!(stdin, "{init}")?;
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )?;
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    )?;
    stdin.flush()?;
    let mut tools = None;
    for _ in 0..20 {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let v: serde_json::Value = serde_json::from_str(line.trim_end())?;
        if v["id"] == 2 {
            let names = v["result"]["tools"]
                .as_array()
                .ok_or("tools array")?
                .iter()
                .map(|t| t["name"].as_str().map(str::to_string).ok_or("tool name"))
                .collect::<Result<Vec<_>, _>>()?;
            tools = Some(names);
            break;
        }
    }
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(tools.ok_or("received no tools/list response")?)
}

#[test]
fn test_mcp_tier_counts_match_the_served_tools() -> TestResult {
    let c = tier_counts();
    let rows: [(&[&str], usize); 6] = [
        (&["--passive"], c.passive),
        (&[], c.default),
        (&["--allow-writes"], c.writes),
        (
            &["--passive", "--no-model-edits"],
            c.passive - c.model_edits,
        ),
        (&["--no-model-edits"], c.default - c.model_edits),
        (&["--allow-programming"], c.default + c.programming),
    ];
    for (flags, expected) in rows {
        let tools = served_tools(flags)?;
        assert_eq!(
            tools.len(),
            expected,
            "`bussard mcp {}` serves {tools:?}",
            flags.join(" ")
        );
    }
    Ok(())
}
