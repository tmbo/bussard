//! The files of a new model directory: `bussard.toml`, `groups.toml`,
//! `devices/`, `captures/`, `.gitignore` and `README.md`, and what is
//! already in the target directory.
//!
//! The `bussard.toml` content is constructed here by hand (three simple keys)
//! rather than via `Model::save`, so the setup is decoupled from the model's
//! emission format.

use std::path::{Path, PathBuf};

use super::gateway::Resolution;
use super::{Context as _, SetupError};
use crate::observer::ProgressSink;

pub use crate::secure::KEYRING_PASSWORD_ENV;

/// Entries that do not make a target directory "non-empty" for `init` and
/// `import`: a repository's own files and bussard's local data.
pub const IGNORED_ENTRIES: &[&str] = &[".git", ".env", ".gitignore", ".bussard"];

/// What is already in the target directory of `init` or `import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TargetState {
    /// Entries other than [`IGNORED_ENTRIES`].
    pub entries: usize,
    /// `knx/bussard.toml` exists below it: a model lives one level down.
    pub nested_model: bool,
}

impl TargetState {
    /// Whether `init` or `import` must ask before writing here.
    pub fn needs_confirmation(self) -> bool {
        self.entries > 0 || self.nested_model
    }

    /// `12 entries, a model exists in knx/`.
    pub fn describe(self) -> String {
        let mut out = match self.entries {
            1 => "1 entry".to_string(),
            n => format!("{n} entries"),
        };
        if self.nested_model {
            out.push_str(&format!(
                ", a model exists in {}/",
                bussard_model::NESTED_MODEL_DIR
            ));
        }
        out
    }
}

/// Reads what is in `dir`. An absent directory is empty.
///
/// # Errors
///
/// `dir` exists but is not a directory, or cannot be listed.
pub fn target_state(dir: &Path) -> Result<TargetState, SetupError> {
    if !dir.exists() {
        return Ok(TargetState::default());
    }
    if !dir.is_dir() {
        return Err(SetupError::Message(format!(
            "{} exists but is not a directory",
            dir.display()
        )));
    }
    let entries = std::fs::read_dir(dir)
        .ctx(|| format!("reading {}", dir.display()))?
        .flatten()
        .filter(|e| !IGNORED_ENTRIES.contains(&e.file_name().to_string_lossy().as_ref()))
        .count();
    let nested_model = dir
        .join(bussard_model::NESTED_MODEL_DIR)
        .join(bussard_model::loader::CONFIG_FILE)
        .is_file();
    Ok(TargetState {
        entries,
        nested_model,
    })
}

/// `the current directory /abs/path` when `dir` is the working directory,
/// else `dir` as given: how a sentence names the model directory.
pub fn describe_dir(dir: &Path) -> String {
    let canonical = |p: &Path| std::fs::canonicalize(p).ok();
    match (canonical(dir), canonical(Path::new("."))) {
        (Some(d), Some(cwd)) if d == cwd => format!("the current directory {}", d.display()),
        _ => dir.display().to_string(),
    }
}

/// What [`find_project`] found next to the model directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSearch {
    /// No `.knxproj`.
    None,
    /// Exactly one.
    One(PathBuf),
    /// Several, sorted; none is picked.
    Several(Vec<PathBuf>),
}

/// The `.knxproj` files next to the model directory (in its parent).
pub fn find_project(dir: &Path) -> ProjectSearch {
    let mut found = files_with_extension(&parent_of(dir), "knxproj");
    match found.len() {
        0 => ProjectSearch::None,
        1 => ProjectSearch::One(found.remove(0)),
        _ => ProjectSearch::Several(found),
    }
}

/// The directory `path` lies in (`.` for a bare name).
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The files in `dir` with extension `ext` (any case), sorted.
fn files_with_extension(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|e| e.eq_ignore_ascii_case(ext))
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// The `.knxkeys` exports in the directory of `project` (sorted).
pub fn neighbour_keyrings(project: &Path) -> Vec<PathBuf> {
    files_with_extension(&parent_of(project), "knxkeys")
}

/// The one `.knxkeys` keyring in the project's directory, to record as
/// `connection.keyring` when no key store can be written (no password).
/// Several are left to the import's message.
pub fn find_keyring(project: &Path) -> Option<PathBuf> {
    let mut found = neighbour_keyrings(project);
    (found.len() == 1).then(|| found.remove(0))
}

/// The `connection.keyring` value for `keyring`, as `bussard.toml` in `dir`
/// resolves it: relative to `dir` when the keyring sits in `dir`'s parent
/// (the usual layout: the ETS exports next to `knx/`), else absolute. The
/// separators are forward slashes on every platform, so the committed
/// `bussard.toml` reads the same on Windows (which accepts `/`).
pub fn keyring_setting(dir: &Path, keyring: &Path) -> String {
    let absolute = |p: &Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let keyring = absolute(keyring);
    let dir = absolute(dir);
    match (keyring.parent(), dir.parent(), keyring.file_name()) {
        (Some(from), Some(parent), Some(name)) if from == parent => {
            format!("../{}", name.to_string_lossy())
        }
        _ => keyring.to_string_lossy().replace('\\', "/"),
    }
}

/// Writes the full model skeleton for the resolved transport. `groups`
/// writes the empty `groups.toml` (not when an import follows); `keyring`
/// records `connection.keyring`.
///
/// # Errors
///
/// A directory or file cannot be written.
pub fn write_skeleton(
    dir: &Path,
    resolution: &Resolution,
    groups: bool,
    keyring: Option<&str>,
    out: &mut dyn ProgressSink,
) -> Result<(), SetupError> {
    std::fs::create_dir_all(dir).ctx(|| format!("creating {}", dir.display()))?;

    let mut config = bussard_toml(resolution);
    if let Some(keyring) = keyring {
        // `[connection]` is the file's only table, so the key lands in it. The
        // path is written as a TOML basic string (escapes included).
        config.push_str(&format!(
            "# The ETS keyring export; its password goes in {KEYRING_PASSWORD_ENV}, never here.\nkeyring = {}\n",
            toml_basic_string(keyring)
        ));
    }
    write_file(&dir.join("bussard.toml"), &config)?;
    if groups {
        write_new(&dir.join("groups.toml"), GROUPS_TOML, out)?;
    }

    let devices_dir = dir.join("devices");
    std::fs::create_dir_all(&devices_dir).ctx(|| format!("creating {}", devices_dir.display()))?;
    write_new(&devices_dir.join(".gitkeep"), DEVICES_GITKEEP, out)?;

    let captures_dir = dir.join("captures");
    std::fs::create_dir_all(&captures_dir)
        .ctx(|| format!("creating {}", captures_dir.display()))?;
    write_new(&captures_dir.join(".gitignore"), CAPTURES_GITIGNORE, out)?;

    merge_gitignore(&dir.join(".gitignore"), out)?;
    write_new(&dir.join("README.md"), README_MD, out)?;

    Ok(())
}

/// `value` as a TOML basic string: quoted, with `\\` and `"` escaped (a
/// Windows path keeps its backslashes).
pub fn toml_basic_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Writes `content` to `path` unless a file is already there (`init` in a
/// non-empty directory keeps the repository's own `README.md` and the like).
fn write_new(path: &Path, content: &str, out: &mut dyn ProgressSink) -> Result<(), SetupError> {
    if path.exists() {
        out.say(&format!("Kept the existing {}.", path.display()));
        return Ok(());
    }
    write_file(path, content)
}

/// Writes the model's `.gitignore`, or appends the lines of it an existing
/// `.gitignore` lacks, so `.bussard/`, `*.knxkeys` and `.env` are always
/// ignored. `init` and an `import` into a fresh directory both call it.
///
/// # Errors
///
/// The file cannot be written.
pub fn merge_gitignore(path: &Path, out: &mut dyn ProgressSink) -> Result<(), SetupError> {
    let Ok(existing) = std::fs::read_to_string(path) else {
        return write_file(path, GITIGNORE);
    };
    let present: std::collections::BTreeSet<&str> = existing.lines().map(str::trim).collect();
    let missing: Vec<&str> = GITIGNORE
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !present.contains(l.trim()))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(
        "\n# bussard: its local data, ETS keyring exports and .env passwords stay out of git.\n",
    );
    for line in &missing {
        text.push_str(line);
        text.push('\n');
    }
    out.say(&format!(
        "Added {} to {}.",
        missing.join(", "),
        path.display()
    ));
    write_file(path, &text)
}

/// Writes `content` to `path`, erroring with the path for context.
fn write_file(path: &Path, content: &str) -> Result<(), SetupError> {
    std::fs::write(path, content).ctx(|| format!("writing {}", path.display()))
}

/// Builds the `bussard.toml` body for the resolved transport.
pub fn bussard_toml(resolution: &Resolution) -> String {
    let header = "\
# bussard connection config. Edit `gateway` if your KNXnet/IP interface moves,
# or switch `transport` to \"routing\" to use multicast instead of a tunnel.
";
    match resolution {
        Resolution::Tunnel(endpoint) => {
            format!("{header}[connection]\ntransport = \"tunnel\"\ngateway = \"{endpoint}\"\n")
        }
        Resolution::Routing => format!(
            "{header}[connection]\ntransport = \"routing\"\nmulticast = \"224.0.23.12:3671\"\n"
        ),
        Resolution::Placeholder => format!(
            "{header}[connection]\ntransport = \"tunnel\"\n\
             # TODO: set your gateway's IP, e.g. \"192.0.2.10:3671\".\n\
             # Find it in your router or Home Assistant KNX config, then run\n\
             # `bussard validate --dir knx` to check it.\n\
             gateway = \"192.0.2.10:3671\"\n"
        ),
    }
}

/// `groups.toml` starter: valid and empty, with a header explaining its role.
const GROUPS_TOML: &str = "\
# Group-address plan. Each entry maps a KNX group address to a name and DPT so
# the monitor can decode telegrams. `bussard import` fills this from an ETS
# export; otherwise add entries by hand or as you learn them from `monitor`.
#
# groups = [
#   { address = \"3/0/4\", name = \"Living Room Blind Move\", dpt = \"1.008\" },
# ]
groups = []
";

/// `devices/.gitkeep`: keeps the empty directory in git and explains its use.
const DEVICES_GITKEEP: &str = "\
# Device files live here as `devices/<address>.toml` (one per KNX device): its
# name, location, parameter values and links (com object to group address).
# The vendor facts behind them live in the generated `bussard.lock`. This file
# just keeps the directory in git while it is empty.
";

/// `captures/.gitignore`: ignore everything, since captures are local artefacts.
const CAPTURES_GITIGNORE: &str = "\
# Telegram captures are local artefacts (SQLite databases) — never commit them.
*
!.gitignore
";

/// `knx/.gitignore`: keep bussard's own history (and the other local
/// artefacts) out of git. The history is bussard's, not the repository's: a git
/// user keeps one history in git and one in `.bussard/`, and `bussard undo`
/// reads bussard's.
const GITIGNORE: &str = "\
# bussard's own history and undo data, and data it regenerates (device facts,
# product models). Local to this machine; `bussard history` and `bussard undo`
# read it. Never commit it.
.bussard/

# ETS keyring exports hold key material under their own password. The key
# store bussard.keys is encrypted and meant to be committed; a .knxkeys dropped
# here is not (import it with `bussard keys import`).
*.knxkeys

# passwords for bussard, read automatically; never commit
.env
";

/// `knx/README.md`: onboarding orientation.
const README_MD: &str = "\
# KNX model (bussard)

This directory is your KNX installation as a model. bussard reads it to decode
the bus and to program your devices. The files are plain TOML, but you never
have to edit them by hand: bussard and an assistant driving it write them for
you.

## History and undo are built in

bussard keeps its own history in `.bussard/history/`. Before bussard writes the
model or a device, it saves a full copy of these files, with a note saying which
command did it and when.

- `bussard status`: what has changed since the last save, in plain sentences.
- `bussard history`: every save, oldest first, one line each.
- `bussard show <n>`: what one save changed.
- `bussard undo`: put the files back to the previous save.

`undo` changes files only. Your devices keep working exactly as they are until
you run `bussard plan <device>` and `bussard apply <device>`, which is where you
confirm the change and it reaches the bus.

Edits made in a text editor are picked up too: the next bussard command records
them as an `external edit` save first, so nothing is lost.

## Backups

- `bussard backup`: read every device's tables into `captures/backups/`
  before your first change. It only reads, so it is safe on a live house.
- `bussard restore <backup-dir> <device>`: write one device back from a backup.
- `bussard export house.bussard`: the whole model and its history as one file.
  Keep a copy on a USB stick in the cabinet. `bussard import house.bussard`
  brings it back on another computer.

## Connect your assistant

    claude mcp add knx -- bussard mcp --dir <this directory>

The assistant can read the model, watch the bus, and edit the model; every edit
is saved to the history first. Only you program devices, with `plan` and `apply`.

The assistant can also set an installation up from nothing: register the server
on an empty folder (`bussard mcp --dir <empty folder>`) and ask it to set up the
house. It starts with `knx_setup`, which does what `bussard init` did here.

## Getting started

1. You have an ETS export: `bussard import project.knxproj --dir .`
2. No ETS project: `bussard reconstruct --line 1.1 --out <new directory>` reads
   what the devices carry into a fresh model. Then ask the assistant to help
   you name the group addresses as you press buttons (`bussard learn` does the
   same in a terminal).
3. `bussard audit` reports what you have and what bussard can do with it.

## Files

- `bussard.toml`: connection config, transport (tunnel or routing) and gateway.
- `groups.toml`: the group-address plan, address to name and DPT.
- `devices/`: one file per device, `devices/<address>.toml` (name, location,
  parameter values, and the links from its com objects to group addresses).
- `bussard.lock`: generated by `bussard import` and `bussard adopt`; the vendor
  facts (product, com objects, parameter refs) behind the device files. Never
  edit it by hand.
- `tests.toml`: optional acceptance tests for `bussard test`.
- `captures/`: local telegram captures and device backups.
- `products/`: the product data (vendor `.knxprod` files, and programs
  extracted once from your ETS export) that `bussard.lock` pins. Keep it:
  bussard cannot regenerate it.
- `.bussard/`: bussard's history (`bussard undo` reads it) and data it
  regenerates.

## If you use git

You do not have to. If you do: commit `bussard.toml`, `groups.toml`,
`bussard.lock`, `devices/` and `tests.toml`. The generated `.gitignore` already
excludes `.bussard/`, which is local to this machine. `products/` holds
copyrighted vendor data: committing it is your decision (a private repository
is the usual case), and a clone without it cannot flash until it is restored. A git user then has two histories, one in git and one in bussard;
`bussard undo` reads bussard's.

Guide for new owners: https://bussard.tmbo.dev/docs/getting-started/first-weekend/
";
