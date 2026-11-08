//! One JSON shape per flow (issue #904).
//!
//! Each flow's outcome is one `#[derive(Serialize)]` struct here in the
//! service, and that struct is the only definition of its shape:
//!
//! - the CLI's `--json` is its plain serialisation, printed under its
//!   [`Report::SCHEMA`] version (the `"schema"` field the CLI adds first);
//! - the MCP result of the same flow is the same object plus the chat
//!   envelope: [`Report::summary`] and [`Report::next_step`], and the job
//!   fields the job table adds (`job`, `started`, `done`, `record`).
//!
//! The envelope is never a second builder: a surface calls the methods on
//! the struct. [`schema`] keeps the version of each shape that has no
//! struct of its own yet.

use bussard_model::change::Labels;
use bussard_model::{IndividualAddress, Model};
use serde::Serialize;

/// A flow's outcome: its data, its schema version, and the chat envelope's
/// words.
pub trait Report: Serialize {
    /// The version of this shape in `--json` (`"schema": n`). It goes up
    /// when a field is removed or renamed, changes its type or its meaning.
    const SCHEMA: u32;

    /// The homeowner's sentence about the outcome (issue #306), in room,
    /// device and channel names; `None` when the flow has none.
    fn summary(&self, _model: &Model) -> Option<String> {
        None
    }

    /// What the assistant does next, `None` when nothing.
    fn next_step(&self) -> Option<String> {
        None
    }
}

/// The version of each `--json` shape that has no [`Report`] struct yet,
/// one constant per shape (see the CLI's `output` module for the rules).
pub mod schema {
    /// `bussard audit --json`.
    pub const AUDIT: u32 = 1;
    /// `bussard backup --json` (the manifest).
    pub const BACKUP: u32 = 1;
    /// `bussard describe --json`.
    pub const DESCRIBE: u32 = 1;
    /// `bussard device --json`.
    pub const DEVICE: u32 = 1;
    /// `bussard diff --json`.
    pub const DIFF: u32 = 1;
    /// `bussard diff --checklist --json`.
    pub const DIFF_CHECKLIST: u32 = 1;
    /// `bussard doc --json` (the documentation model).
    pub const DOC: u32 = 1;
    /// `bussard export --json`.
    pub const EXPORT: u32 = 1;
    /// `bussard groups reserve --json`.
    pub const GROUPS_RESERVE: u32 = 1;
    /// `bussard groups secure --json`.
    pub const GROUPS_SECURE: u32 = 1;
    /// `bussard history --json`: `{ "snapshots": [...] }`.
    pub const HISTORY: u32 = 1;
    /// `bussard interface secure --json` (issue #398).
    pub const INTERFACE_SECURE: u32 = 1;
    /// `bussard keys add-certificate --json`.
    pub const KEYS_ADD_CERTIFICATE: u32 = 1;
    /// `bussard keys enroll --json`: one object per line (issue #729).
    pub const KEYS_ENROLL: u32 = 1;
    /// `bussard keys export --json`.
    pub const KEYS_EXPORT: u32 = 1;
    /// `bussard keys import --json`.
    pub const KEYS_IMPORT: u32 = 1;
    /// `bussard keys show --json`.
    pub const KEYS_SHOW: u32 = 1;
    /// `bussard monitor --json`: one object per line.
    pub const MONITOR: u32 = 1;
    /// `bussard read --json`.
    pub const READ: u32 = 1;
    /// `bussard reconstruct --json`.
    pub const RECONSTRUCT: u32 = 1;
    /// `bussard reconstruct --line --json`.
    pub const RECONSTRUCT_LINE: u32 = 1;
    /// `bussard scan --json`.
    pub const SCAN: u32 = 1;
    /// `bussard secure diag <ADDRESS> --json` (issue #533).
    pub const SECURE_DIAG: u32 = 1;
    /// `bussard show --json`.
    pub const SHOW: u32 = 1;
    /// `bussard status --json`.
    pub const STATUS: u32 = 1;
    /// `bussard status <ADDRESS> --json`: one device's live state (issue #391).
    pub const STATUS_DEVICE: u32 = 1;
    /// `bussard test --json`.
    pub const TEST: u32 = 1;
    /// `bussard test --secure-idle --json`.
    pub const TEST_SECURE_IDLE: u32 = 1;
    /// `bussard undo --json`.
    pub const UNDO: u32 = 1;
    /// `bussard validate --json`: `{ "diagnostics": [...] }`.
    pub const VALIDATE: u32 = 1;
    /// `bussard write --json`.
    pub const WRITE: u32 = 1;
}

/// A device as the human knows it: `Hallway push button in Hallway`, its
/// name alone when it has no room, `device 1.1.4` when it has no name. A
/// name another device shares carries the address.
pub fn device_phrase(model: &Model, ia: IndividualAddress) -> String {
    let device = model.devices.get(&ia).map(|d| &d.device);
    let named = device.is_some_and(|d| !d.name.trim().is_empty());
    let name = if named {
        Labels::plain([model, model]).device(ia)
    } else {
        format!("device {ia}")
    };
    match room_of(model, ia) {
        Some(room) => format!("{name} in {room}"),
        None => name,
    }
}

/// A com object as the human reads it: `Eingang 1 of Logikkanal C18`, the
/// link's name or the vendor's object text, of the channel's name or text;
/// `function <n>` when nothing names it.
pub fn object_phrase(model: &Model, ia: IndividualAddress, object: u16) -> String {
    let device = model.devices.get(&ia).map(|d| &d.device);
    let co = device.and_then(|d| d.com_objects.get(&object));
    let link_name = model
        .links
        .links
        .get(&ia)
        .and_then(|links| links.iter().find(|l| l.object == object))
        .and_then(|l| l.name.as_deref());
    let channel_names: Vec<&str> = co
        .and_then(|c| c.channel.as_deref())
        .and_then(|id| device?.channels.get(id))
        .map(|ch| {
            [Some(ch.name.as_str()), ch.text.as_deref()]
                .into_iter()
                .flatten()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let channel = channel_names.first().copied();
    // A vendor text that only repeats the channel is skipped for the
    // function text (as the change sentences do).
    let texts: Vec<&str> = [
        co.and_then(|c| c.text.as_deref()),
        co.and_then(|c| c.function.as_deref()),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .collect();
    let name = link_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            texts
                .iter()
                .find(|t| !channel_names.contains(t))
                .or_else(|| texts.first())
                .copied()
        });
    match (name, channel) {
        (Some(n), Some(c)) if n != c => format!("{n} of {c}"),
        (Some(n), _) => n.to_string(),
        (None, Some(c)) => c.to_string(),
        (None, None) => format!("function {object}"),
    }
}

/// The room of device `ia` (`Hallway`, `Hallway, EG`), when the model says.
pub fn room_of(model: &Model, ia: IndividualAddress) -> Option<String> {
    let location = model.devices.get(&ia)?.device.location.as_ref()?;
    let room = location
        .room
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let floor = location
        .floor
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (room, floor) {
        (Some(r), Some(f)) => Some(format!("{r}, {f}")),
        (Some(r), None) => Some(r.to_string()),
        (None, Some(f)) => Some(f.to_string()),
        (None, None) => None,
    }
}

/// The device an outcome is about, as a phrase: `address` parsed, or every
/// device of `line`, or `the device`.
pub fn subject_phrase(model: &Model, address: Option<&str>, line: Option<&str>) -> String {
    match address.and_then(|a| a.parse::<IndividualAddress>().ok()) {
        Some(ia) => device_phrase(model, ia),
        None => match line {
            Some(line) => format!("every device on line {line}"),
            None => "the device".to_string(),
        },
    }
}

/// A refusal (issue #904): `ok: false`, `refused: true` and the reason, a
/// normal result rather than a protocol error, so the assistant reads the
/// reason out to the human. Nothing was written.
#[derive(Debug, Clone, Serialize)]
pub struct Refusal {
    /// Always `false`.
    pub ok: bool,
    /// Always `true`.
    pub refused: bool,
    /// Why.
    pub reason: String,
    /// The device the refused request was about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The line the refused request was about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
}

impl Refusal {
    /// A refusal because `reason`.
    pub fn new(reason: impl Into<String>) -> Refusal {
        Refusal {
            ok: false,
            refused: true,
            reason: reason.into(),
            address: None,
            line: None,
        }
    }
}

impl Report for Refusal {
    const SCHEMA: u32 = 1;

    fn summary(&self, model: &Model) -> Option<String> {
        let device = subject_phrase(model, self.address.as_deref(), self.line.as_deref());
        Some(format!(
            "Nothing was changed: bussard refused this request (`reason` says why){}.",
            if self.address.is_some() {
                format!("; {device} is as it was")
            } else {
                String::new()
            }
        ))
    }
}

/// What a plan asks before anything is written: the one question, and on
/// the MCP surface the digest that names the plan and when it expires (the
/// CLI asks on the terminal and has no digest).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Approval {
    /// The one question the write asks; absent when there is nothing to
    /// write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    /// The digest the write takes after the human's yes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<String>,
    /// When the digest expires, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl Approval {
    /// The question alone (the CLI's plan).
    pub fn question(question: Option<String>) -> Approval {
        Approval {
            question,
            ..Approval::default()
        }
    }

    /// Whether the plan waits for a yes (it has a digest).
    pub fn pending(&self) -> bool {
        self.plan_digest.is_some()
    }
}

/// ` (3 changes)` for `n` changes, nothing for none.
pub fn counted(n: usize) -> String {
    match n {
        0 => String::new(),
        1 => " (1 change)".to_string(),
        n => format!(" ({n} changes)"),
    }
}

/// `true` for `false` (a serde `skip_serializing_if` helper).
pub fn is_false(b: &bool) -> bool {
    !*b
}
