//! Model-edit and history tools (issues #110, #112).
//!
//! bussard's primary operator is an assistant driving this server for a
//! homeowner who does not read TOML. So the model is edited through structured
//! tools here, never by the assistant hand-writing files, and every edit:
//!
//! 1. takes a history snapshot of the current files first,
//! 2. applies one well-defined change,
//! 3. saves and validates, and
//! 4. returns the change as plain-language sentences plus the snapshot id.
//!
//! Nothing here touches the bus. A model edit changes model files only; a human
//! still runs `bussard plan` and `bussard apply` to push it to a device. Every
//! tool description says so, because the caller has to say so to the human.
//!
//! Protected group addresses (`protected: true`) are refused outright, exactly
//! as `knx_write_group` refuses them: there is no MCP override, and no tool
//! parameter can set or clear the flag.

use std::path::Path;

use bussard_model::change::{ChangeSet, describe};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::param_model::{ProductModels, key_to_param_id};
use bussard_model::schema::{Group, Link, Location};
use bussard_model::{Dpt, GroupAddress, IndividualAddress, Model, Severity};
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::server::BussardMcp;

/// Arguments for `knx_describe_change`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DescribeChangeArgs {
    /// The snapshot to compare from (its id, or its number in `knx_history`).
    /// Defaults to the latest snapshot.
    #[serde(default)]
    pub from: Option<String>,
    /// The snapshot to compare to. Defaults to the working model on disk, i.e.
    /// the changes that have not been pushed to any device yet.
    #[serde(default)]
    pub to: Option<String>,
}

/// Arguments for `knx_history`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct HistoryArgs {
    /// Maximum snapshots to return, newest last (default 50).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for `knx_set_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetGroupArgs {
    /// The group address, e.g. `"0/0/4"`.
    pub ga: String,
    /// The display name. Required when the group address is new.
    #[serde(default)]
    pub name: Option<String>,
    /// The datapoint type, e.g. `"1.001"`.
    #[serde(default)]
    pub dpt: Option<String>,
    /// A free-text note for the humans reading the model.
    #[serde(default)]
    pub description: Option<String>,
}

/// Arguments for `knx_add_link` and `knx_remove_link`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LinkArgs {
    /// The device's individual address, e.g. `"1.1.4"`.
    pub device: String,
    /// The ETS com-object number on that device.
    pub com_object: u16,
    /// The group address to bind or unbind, e.g. `"0/0/4"`.
    pub ga: String,
    /// `"send"` (the com object transmits on this GA) or `"listen"` (it reacts
    /// to it). A com object has at most one sending GA and any number of
    /// listening ones.
    pub role: String,
}

/// Arguments for `knx_set_device`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetDeviceArgs {
    /// The device's individual address, e.g. `"1.1.4"`.
    pub address: String,
    /// A new display name.
    #[serde(default)]
    pub name: Option<String>,
    /// A new floor, e.g. `"EG"`.
    #[serde(default)]
    pub floor: Option<String>,
    /// A new room, e.g. `"Wohnzimmer"`.
    #[serde(default)]
    pub room: Option<String>,
}

/// Arguments for `knx_set_parameter`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetParameterArgs {
    /// The device's individual address, e.g. `"1.1.4"`.
    pub address: String,
    /// The parameter key as the device file uses it (`knx_show_device` lists
    /// them), e.g. `"betriebsart"`, `"sollwerte.komfort"`, or the escape-hatch
    /// form `"nachtabsenkung@P-1312_R-2140"`.
    pub parameter: String,
    /// The channel handle the parameter sits in (`"a-1"`), when the key alone
    /// is not unique on the device.
    #[serde(default)]
    pub channel: Option<String>,
    /// The new value: an enum label (`"Jalousie"`) or code, a number, or text.
    pub value: String,
}

/// Arguments for `knx_undo`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct UndoArgs {
    /// The snapshot to restore (its id, or its number in `knx_history`).
    /// Defaults to the newest snapshot that differs from the current files,
    /// which undoes the last change.
    #[serde(default)]
    pub snapshot_id: Option<String>,
}

/// The names of the tools that edit the model, removed from the router when the
/// server is started with `--no-model-edits`.
///
/// `knx_scaffold_groups` and `knx_reserve_groups` live on the group-planning
/// router but write `groups.toml`, so they are withheld with the others.
pub const MODEL_EDIT_TOOLS: [&str; 8] = [
    "knx_scaffold_groups",
    "knx_reserve_groups",
    "knx_set_group",
    "knx_add_link",
    "knx_remove_link",
    "knx_set_device",
    "knx_set_parameter",
    "knx_undo",
];

/// The read-only model/history tools, available in every tier.
pub const MODEL_READ_TOOLS: [&str; 2] = ["knx_describe_change", "knx_history"];

// `pub(crate)`: the router is combined in `BussardMcp::new` and needs no public
// face (a `pub` macro-generated fn could not carry the doc comment the crate
// requires).
#[tool_router(router = model_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_describe_change`.
    #[tool(
        description = "Describe a model change in plain sentences a homeowner can judge, e.g. \
        \"Rocker 1 on Hallway push button now switches Porch light (0/0/4).\" With no arguments it \
        describes the PENDING changes: the model files as they are now against the last history \
        snapshot, i.e. everything edited but not yet pushed to any device. Pass `from` and `to` \
        snapshot ids (from knx_history) to describe the change between two snapshots instead. \
        QUOTE THESE SENTENCES TO THE HUMAN before she confirms anything; a change marked \
        touches_protected concerns a safety-critical group address and needs her explicit word."
    )]
    async fn knx_describe_change(
        &self,
        Parameters(args): Parameters<DescribeChangeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let dir = self.state().dir.clone();
        let history = History::open(&dir);

        let to_model = match &args.to {
            Some(spec) => match resolve_model(&history, spec) {
                Ok(model) => model,
                Err(reason) => return refusal(reason),
            },
            None => match Model::load(&dir) {
                Ok(model) => model,
                Err(err) => return refusal(format!("the working model does not load: {err}")),
            },
        };

        let (base, from_model) = match &args.from {
            Some(spec) => match resolve_model(&history, spec) {
                Ok(model) => (Some(spec.clone()), model),
                Err(reason) => return refusal(reason),
            },
            None => match history.latest() {
                Ok(Some(latest)) => match history.load(&latest.id) {
                    Ok(model) => (Some(latest.id.to_string()), model),
                    Err(err) => {
                        return refusal(format!("snapshot {} does not load: {err}", latest.id));
                    }
                },
                Ok(None) => {
                    return ok(json!({
                        "ok": true,
                        "base": Value::Null,
                        "changes": [],
                        "sentences": [],
                        "note": "no history snapshot yet, so there is nothing to compare against",
                    }));
                }
                Err(err) => return refusal(format!("the history could not be read: {err}")),
            },
        };

        let changes = describe(&from_model, &to_model);
        ok(change_json(base, &changes))
    }

    /// `knx_history`.
    #[tool(
        description = "List the model's history snapshots, oldest first: id, time, the command \
        that caused it, the gateway it wrote to (if any) and a one-line plain-language summary of \
        what it changed. Use it to answer \"what did we change, and when?\", and to get a snapshot \
        id for knx_describe_change or knx_undo."
    )]
    async fn knx_history(
        &self,
        Parameters(args): Parameters<HistoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let history = History::open(&self.state().dir);
        let snapshots = match history.list() {
            Ok(snapshots) => snapshots,
            Err(err) => return refusal(format!("the history could not be read: {err}")),
        };
        let limit = args.limit.unwrap_or(50).clamp(1, 500) as usize;
        let start = snapshots.len().saturating_sub(limit);

        let mut rows = Vec::new();
        for (index, snapshot) in snapshots.iter().enumerate().skip(start) {
            let summary = match index.checked_sub(1) {
                Some(previous) => {
                    match (
                        history.load(&snapshots[previous].id),
                        history.load(&snapshot.id),
                    ) {
                        (Ok(old), Ok(new)) => describe(&old, &new).summary(),
                        _ => String::new(),
                    }
                }
                None => "the first snapshot of the model".to_string(),
            };
            rows.push(json!({
                "index": index + 1,
                "id": snapshot.id,
                "created_at": snapshot.manifest.created_at,
                "command": snapshot.manifest.reason.command,
                "args": snapshot.manifest.reason.args,
                "gateway": snapshot.manifest.gateway,
                "result": snapshot.manifest.result,
                "summary": summary,
            }));
        }
        ok(json!({ "ok": true, "count": rows.len(), "snapshots": rows }))
    }

    /// `knx_set_group`.
    #[tool(
        description = "Create or update a group address in groups.toml: its name, datapoint type \
        and free-text note. Creating one needs a name. This edits FILES ONLY — no telegram is sent \
        and no device is touched until a human runs `bussard plan` and `bussard apply`. A group \
        address marked protected (safety-critical, e.g. a wind alarm) cannot be renamed or retyped \
        here, and there is deliberately no way to set or clear that flag over MCP. Returns the \
        change as sentences: quote them to the human."
    )]
    async fn knx_set_group(
        &self,
        Parameters(args): Parameters<SetGroupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ga: GroupAddress = match args.ga.parse() {
            Ok(ga) => ga,
            Err(_) => {
                return refusal(format!(
                    "{:?} is not a group address like \"0/0/4\"",
                    args.ga
                ));
            }
        };
        let dpt: Option<Dpt> = match args.dpt.as_deref() {
            Some(raw) => match raw.parse() {
                Ok(dpt) => Some(dpt),
                Err(_) => {
                    return refusal(format!("{raw:?} is not a datapoint type like \"1.001\""));
                }
            },
            None => None,
        };
        let description = args.description.clone();
        let name = args.name.clone();
        let summary = format!("{ga}");

        self.edit("knx_set_group", vec![summary], move |model| {
            match model.groups.groups.get_mut(&ga) {
                Some(group) => {
                    if group.protected {
                        let renaming = name.as_deref().is_some_and(|n| n != group.name);
                        let retyping = dpt.is_some() && dpt != group.dpt;
                        if renaming || retyping {
                            return Err(format!(
                                "{ga} ({:?}) is protected: renaming or retyping it is refused over \
                                 MCP. A human can edit groups.toml directly.",
                                group.name
                            ));
                        }
                    }
                    if let Some(name) = name {
                        group.name = name;
                    }
                    if let Some(dpt) = dpt {
                        group.dpt = Some(dpt);
                    }
                    if let Some(description) = description {
                        group.description = Some(description);
                    }
                }
                None => {
                    let Some(name) = name else {
                        return Err(format!(
                            "{ga} is not in the model yet; pass `name` to create it"
                        ));
                    };
                    model.groups.groups.insert(
                        ga,
                        Group {
                            name,
                            dpt,
                            description,
                            protected: false,
                            secure: false,
                        },
                    );
                }
            }
            Ok(())
        })
    }

    /// `knx_add_link`.
    #[tool(
        description = "Bind a device's com object to a group address in its device file (devices/<address>.toml): role \"send\" \
        makes the com object transmit on that GA (a com object has at most one, so an existing one \
        is replaced), role \"listen\" makes it react to the GA. A GA that groups.toml does not \
        define yet is added there, named `<channel or device name> <object function>` with the \
        object's DPT, and reported in groups_declared. This edits FILES ONLY — the device \
        keeps its current wiring until a human runs `bussard plan <ia>` and `bussard apply <ia>`. \
        Protected group addresses are refused outright. Returns the change as sentences: quote \
        them to the human before she confirms."
    )]
    async fn knx_add_link(
        &self,
        Parameters(args): Parameters<LinkArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let (ia, ga, role) = match parse_link_args(&args) {
            Ok(parsed) => parsed,
            Err(reason) => return refusal(reason),
        };
        let object = args.com_object;
        let label = vec![
            ia.to_string(),
            object.to_string(),
            ga.to_string(),
            role.tag().to_string(),
        ];

        self.edit("knx_add_link", label, move |model| {
            refuse_protected(model, ga)?;
            if !model.devices.contains_key(&ia) {
                return Err(format!(
                    "{ia} is not a device in this model; add its device file first"
                ));
            }
            // Read what the com object already binds before taking a mutable
            // borrow, so the protected check can still see the whole model.
            let existing_send = model
                .links
                .links
                .get(&ia)
                .and_then(|links| links.iter().find(|l| l.object == object))
                .and_then(|l| l.send);
            if role == Role::Send {
                if existing_send == Some(ga) {
                    return Err(format!("com object {object} on {ia} already sends to {ga}"));
                }
                if let Some(existing) = existing_send {
                    // Replacing a send GA unbinds the old one, so the old one is
                    // touched too and a protected one blocks the edit.
                    refuse_protected(model, existing)?;
                }
            }

            let links = model.links.links.entry(ia).or_default();
            if !links.iter().any(|l| l.object == object) {
                links.push(Link {
                    object,
                    name: None,
                    send: None,
                    listen: Vec::new(),
                });
                links.sort_by_key(|l| l.object);
            }
            let link = links
                .iter_mut()
                .find(|l| l.object == object)
                .ok_or_else(|| format!("com object {object} on {ia} could not be created"))?;
            match role {
                Role::Send => link.send = Some(ga),
                Role::Listen => {
                    if link.listen.contains(&ga) {
                        return Err(format!(
                            "com object {object} on {ia} already listens to {ga}"
                        ));
                    }
                    link.listen.push(ga);
                    link.listen.sort();
                }
            }
            Ok(())
        })
    }

    /// `knx_remove_link`.
    #[tool(
        description = "Unbind a device's com object from a group address in its device file (devices/<address>.toml) (role \
        \"send\" or \"listen\"). This edits FILES ONLY — the device keeps its current wiring until \
        a human runs `bussard plan <ia>` and `bussard apply <ia>`. Protected group addresses are \
        refused outright. Returns the change as sentences: quote them to the human."
    )]
    async fn knx_remove_link(
        &self,
        Parameters(args): Parameters<LinkArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let (ia, ga, role) = match parse_link_args(&args) {
            Ok(parsed) => parsed,
            Err(reason) => return refusal(reason),
        };
        let object = args.com_object;
        let label = vec![
            ia.to_string(),
            object.to_string(),
            ga.to_string(),
            role.tag().to_string(),
        ];

        self.edit("knx_remove_link", label, move |model| {
            refuse_protected(model, ga)?;
            let Some(links) = model.links.links.get_mut(&ia) else {
                return Err(format!("{ia} has no links in this model"));
            };
            let Some(link) = links.iter_mut().find(|l| l.object == object) else {
                return Err(format!(
                    "com object {object} on {ia} has no links in this model"
                ));
            };
            match role {
                Role::Send => {
                    if link.send != Some(ga) {
                        return Err(format!("com object {object} on {ia} does not send to {ga}"));
                    }
                    link.send = None;
                }
                Role::Listen => {
                    let before = link.listen.len();
                    link.listen.retain(|g| *g != ga);
                    if link.listen.len() == before {
                        return Err(format!(
                            "com object {object} on {ia} does not listen to {ga}"
                        ));
                    }
                }
            }
            Ok(())
        })
    }

    /// `knx_set_device`.
    #[tool(
        description = "Rename a device or change where it lives (floor and room) in its \
        devices/*.toml file. Names and locations are what every other sentence is built from, so \
        good ones make the whole model readable. This edits FILES ONLY and never touches the bus. \
        Returns the change as sentences: quote them to the human."
    )]
    async fn knx_set_device(
        &self,
        Parameters(args): Parameters<SetDeviceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ia: IndividualAddress = match args.address.parse() {
            Ok(ia) => ia,
            Err(_) => {
                return refusal(format!(
                    "{:?} is not an individual address like \"1.1.4\"",
                    args.address
                ));
            }
        };
        if args.name.is_none() && args.floor.is_none() && args.room.is_none() {
            return refusal("nothing to change: pass at least one of name, floor or room");
        }
        let (name, floor, room) = (args.name.clone(), args.floor.clone(), args.room.clone());

        self.edit("knx_set_device", vec![ia.to_string()], move |model| {
            let Some(loaded) = model.devices.get_mut(&ia) else {
                return Err(format!("{ia} is not a device in this model"));
            };
            if let Some(name) = name {
                if name.trim().is_empty() {
                    return Err("a device name cannot be empty".to_string());
                }
                loaded.device.name = name;
            }
            if floor.is_some() || room.is_some() {
                let location = loaded.device.location.get_or_insert(Location {
                    floor: None,
                    room: None,
                });
                if let Some(floor) = floor {
                    location.floor = Some(floor);
                }
                if let Some(room) = room {
                    location.room = Some(room);
                }
            }
            Ok(())
        })
    }

    /// `knx_set_parameter`.
    #[tool(
        description = "Change one device parameter value in its device file, devices/<address>.toml \
        (e.g. a night setback temperature). `parameter` is the key the file uses, as \
        knx_show_device lists it (add `channel` when the key repeats across channels); any \
        parameter the lock knows for the device can be set, and the value (an enum label or \
        code, a number) is checked against the vendor's product model first; without a product \
        model the edit is refused rather than guessed. This edits FILES ONLY — the device keeps \
        its current settings until a human runs `bussard plan <ia>` and `bussard apply <ia>`. \
        Returns the change as sentences: quote them to the human."
    )]
    async fn knx_set_parameter(
        &self,
        Parameters(args): Parameters<SetParameterArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ia: IndividualAddress = match args.address.parse() {
            Ok(ia) => ia,
            Err(_) => {
                return refusal(format!(
                    "{:?} is not an individual address like \"1.1.4\"",
                    args.address
                ));
            }
        };
        let dir = self.state().dir.clone();
        let (wanted, value) = (args.parameter.clone(), args.value.clone());
        let channel = args.channel.clone();
        let label = vec![ia.to_string(), wanted.clone(), value.clone()];

        self.edit("knx_set_parameter", label, move |model| {
            let Some(loaded) = model.devices.get_mut(&ia) else {
                return Err(format!("{ia} is not a device in this model"));
            };
            let key = resolve_parameter_key(&loaded.device, &wanted, channel.as_deref())?;
            let value = check_parameter(&dir, loaded, &key, &value)?;
            loaded.device.parameters.insert(key, value);
            Ok(())
        })
    }

    /// `knx_undo`.
    #[tool(
        description = "Put the model files back to a history snapshot (default: the newest \
        snapshot that differs from the current files, i.e. undo the last change). This changes FILES ONLY: devices keep whatever is in their tables until a \
        human runs `bussard plan <ia>` and `bussard apply <ia>`. The state before the undo is \
        itself snapshotted, so an undo can be undone. Returns what the undo reverted, as \
        sentences: quote them to the human."
    )]
    async fn knx_undo(
        &self,
        Parameters(args): Parameters<UndoArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if self.state().no_model_edits {
            return refusal("this server was started with --no-model-edits");
        }
        let dir = self.state().dir.clone();
        let history = History::open(&dir);
        let snapshots = match history.list() {
            Ok(snapshots) => snapshots,
            Err(err) => return refusal(format!("the history could not be read: {err}")),
        };
        if snapshots.is_empty() {
            return refusal("there are no history snapshots yet, so there is nothing to undo");
        }
        let target = match &args.snapshot_id {
            Some(spec) => match history.resolve(spec) {
                Ok(snapshot) => snapshot,
                Err(err) => return refusal(err.to_string()),
            },
            None => match history.undo_target() {
                Ok(Some(snapshot)) => snapshot,
                Ok(None) => {
                    return refusal(
                        "the model files already match every snapshot, so there is nothing to undo",
                    );
                }
                Err(err) => return refusal(format!("the history could not be read: {err}")),
            },
        };

        let before = Model::load(&dir).ok();
        let restored = match history.load(&target.id) {
            Ok(model) => model,
            Err(err) => return refusal(format!("snapshot {} does not load: {err}", target.id)),
        };
        let changes = before
            .as_ref()
            .map(|b| describe(b, &restored))
            .unwrap_or_default();

        let undo_snapshot = match history.restore(&target.id) {
            Ok(id) => id,
            Err(err) => return refusal(format!("the restore failed: {err}")),
        };
        self.state().model.reload();

        let diagnostics = bussard_model::validate_in_dir(&restored, &dir);
        ok(json!({
            "ok": true,
            "restored": target.id,
            "snapshot": undo_snapshot,
            "changes": sentences(&changes),
            "detail": changes.changes,
            "validation": validation_json(&diagnostics),
            "next_step": "Nothing has reached any device. A human runs `bussard plan <ia>` and \
                          `bussard apply <ia>` to push this to the bus.",
        }))
    }
}

impl BussardMcp {
    /// The shared edit ladder: load, apply, snapshot, save, validate, describe.
    ///
    /// The model is re-read from disk rather than taken from the cached handle,
    /// so an edit never silently reverts a change a human made in an editor a
    /// second ago. The snapshot is taken after the edit has been computed (a
    /// refused edit leaves no trace) and before anything is written.
    fn edit<F>(&self, tool: &str, args: Vec<String>, apply: F) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(&mut Model) -> Result<(), String>,
    {
        if self.state().no_model_edits {
            return refusal("this server was started with --no-model-edits");
        }
        let dir = self.state().dir.clone();
        let before = match Model::load(&dir) {
            Ok(model) => model,
            Err(err) => {
                return refusal(format!(
                    "the model at {} does not load: {err}",
                    dir.display()
                ));
            }
        };
        let mut edited = before.clone();
        if let Err(reason) = apply(&mut edited) {
            return refusal(reason);
        }
        // A group address the edit links but groups.toml does not define is
        // declared there, named after the object that uses it first; the
        // change set below reports it with the rest.
        let declared: Vec<String> = bussard_model::declare_used_groups(&mut edited)
            .iter()
            .map(|d| d.sentence())
            .collect();
        let changes = describe(&before, &edited);
        if changes.is_empty() {
            return ok(json!({
                "ok": true,
                "changes": [],
                "note": "the model already said that; nothing was written",
            }));
        }

        let reason = SnapshotReason::new(format!("mcp {tool}"))
            .with_args(args)
            .with_result("before an MCP model edit");
        let snapshot = match History::open(&dir).snapshot(reason) {
            Ok(id) => id,
            Err(err) => {
                return refusal(format!(
                    "refusing to edit: the history snapshot could not be written ({err})"
                ));
            }
        };

        if let Err(err) = edited.save(&dir) {
            return refusal(format!("the model could not be saved: {err}"));
        }
        // The handle debounces its directory check; force it so the very next
        // tool call sees what we just wrote.
        self.state().model.reload();

        let diagnostics = bussard_model::validate_in_dir(&edited, &dir);
        ok(json!({
            "ok": true,
            "snapshot": snapshot,
            "changes": sentences(&changes),
            "detail": changes.changes,
            "touches_protected": changes.touches_protected(),
            "groups_declared": declared,
            "validation": validation_json(&diagnostics),
            "next_step": "Nothing has reached any device. A human runs `bussard plan <ia>` and \
                          `bussard apply <ia>` to push this to the bus.",
        }))
    }
}

/// Which side of a link a group address sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The com object's single sending GA.
    Send,
    /// One of the com object's listening GAs.
    Listen,
}

impl Role {
    /// The wire tag (`"send"` / `"listen"`).
    fn tag(self) -> &'static str {
        match self {
            Role::Send => "send",
            Role::Listen => "listen",
        }
    }
}

/// Parses the shared link-tool arguments.
fn parse_link_args(args: &LinkArgs) -> Result<(IndividualAddress, GroupAddress, Role), String> {
    let ia: IndividualAddress = args.device.parse().map_err(|_| {
        format!(
            "{:?} is not an individual address like \"1.1.4\"",
            args.device
        )
    })?;
    let ga: GroupAddress = args
        .ga
        .parse()
        .map_err(|_| format!("{:?} is not a group address like \"0/0/4\"", args.ga))?;
    let role = match args.role.to_ascii_lowercase().as_str() {
        "send" => Role::Send,
        "listen" => Role::Listen,
        other => {
            return Err(format!(
                "role must be \"send\" or \"listen\", not {other:?}"
            ));
        }
    };
    Ok((ia, ga, role))
}

/// Whether a GA is protected in `groups`.
fn model_groups_protected(groups: &bussard_model::schema::Groups, ga: GroupAddress) -> bool {
    groups.groups.get(&ga).is_some_and(|g| g.protected)
}

/// Refuses an edit that touches a protected GA.
fn refuse_protected(model: &Model, ga: GroupAddress) -> Result<(), String> {
    refuse_protected_ga(model_groups_protected(&model.groups, ga), ga)
}

/// The refusal message for a protected GA, shared by both link tools.
fn refuse_protected_ga(protected: bool, ga: GroupAddress) -> Result<(), String> {
    if protected {
        Err(format!(
            "{ga} is protected (safety-critical). Links touching it are refused over MCP; a human \
             can edit the device file (devices/<address>.toml) directly."
        ))
    } else {
        Ok(())
    }
}

/// Validates a parameter value against the vendor product model, refusing when
/// there is no model to check it against.
/// The in-memory key (`<slug>@<ref>`) of the parameter a device file names
/// `wanted` (in `channel`, when given): an in-memory key as is, else the one
/// lock entry with that file key.
fn resolve_parameter_key(
    device: &bussard_model::schema::Device,
    wanted: &str,
    channel: Option<&str>,
) -> Result<String, String> {
    if device.parameters.contains_key(wanted) {
        return Ok(wanted.to_string());
    }
    let hits: Vec<(&String, &bussard_model::schema::LockedParameter)> = device
        .lock
        .parameters
        .iter()
        .filter(|(_, p)| p.key == wanted)
        .filter(|(_, p)| match channel {
            Some(h) => {
                p.channel
                    .as_deref()
                    .map(|id| device.channel_handle(id))
                    .as_deref()
                    == Some(h)
            }
            None => true,
        })
        .collect();
    match hits.as_slice() {
        [(reference, _)] => Ok(device
            .parameters
            .keys()
            .find(|k| {
                k.split_once('@')
                    .is_some_and(|(_, r)| r == reference.as_str())
            })
            .cloned()
            .unwrap_or_else(|| format!("{}@{reference}", bussard_model::slug(wanted)))),
        [] => Err(format!(
            "{} has no parameter {wanted:?}{}. knx_show_device lists the keys the device file \
             accepts.",
            device.address,
            channel
                .map(|c| format!(" in channel {c}"))
                .unwrap_or_default()
        )),
        many => Err(format!(
            "{wanted:?} names a parameter in several channels of {} ({}); pass `channel`",
            device.address,
            many.iter()
                .map(|(_, p)| p
                    .channel
                    .as_deref()
                    .map(|id| device.channel_handle(id))
                    .unwrap_or_else(|| "device".to_string()))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Checks `value` for the parameter `key` against the product model and
/// returns it as the model stores it (an enum label becomes its code).
fn check_parameter(
    dir: &Path,
    loaded: &bussard_model::LoadedDevice,
    key: &str,
    value: &str,
) -> Result<String, String> {
    let app_ref = loaded
        .device
        .product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref())
        .ok_or_else(|| {
            format!(
                "{} declares no product.application_ref, so its parameters cannot be checked. \
                 Import the product data first (`bussard import-product`).",
                loaded.device.address
            )
        })?;
    let models = ProductModels::load(dir);
    let product = models.get(app_ref).ok_or_else(|| {
        format!(
            "no product model for {app_ref} under {}/models. Run `bussard import-product` so the \
             value can be range-checked; refusing to guess.",
            dir.display()
        )
    })?;
    let param_id = key_to_param_id(key).ok_or_else(|| {
        format!("parameter key {key:?} is malformed (expected `<name>@<ref-id>`)")
    })?;
    let def = product.parameters.get(&param_id).ok_or_else(|| {
        format!("{param_id:?} (from key {key:?}) is not a parameter of {app_ref}")
    })?;
    let value = bussard_model::param_model::enum_code(&def.labels, value)
        .map(|code| code.to_string())
        .unwrap_or_else(|| value.to_string());
    match bussard_model::validate::parameter_value_error(&def.kind, &value) {
        Some(reason) => Err(reason),
        None => Ok(value),
    }
}

/// Loads the model at a snapshot named by id or index.
fn resolve_model(history: &History, spec: &str) -> Result<Model, String> {
    let snapshot = history.resolve(spec).map_err(|e| e.to_string())?;
    history.load(&snapshot.id).map_err(|e| e.to_string())
}

/// The sentences of a change set, in rendering order (protected first).
fn sentences(changes: &ChangeSet) -> Vec<String> {
    bussard_model::change::render_text(changes)
        .lines()
        .map(str::to_string)
        .collect()
}

/// The `{base, changes, sentences}` payload `knx_describe_change` returns.
fn change_json(base: Option<String>, changes: &ChangeSet) -> Value {
    json!({
        "ok": true,
        "base": base,
        "count": changes.len(),
        "touches_protected": changes.touches_protected(),
        "sentences": sentences(changes),
        "changes": changes.changes,
        "note": "Nothing here has reached any device: these are model files only.",
    })
}

/// The `{errors, warnings}` validation payload every edit tool returns.
fn validation_json(diagnostics: &[bussard_model::Diagnostic]) -> Value {
    let pick = |severity: Severity| -> Vec<Value> {
        diagnostics
            .iter()
            .filter(|d| d.severity == severity)
            .map(|d| {
                json!({
                    "code": d.code,
                    "message": d.message,
                    "location": d.location,
                })
            })
            .collect()
    };
    let errors = pick(Severity::Error);
    let warnings = pick(Severity::Warning);
    json!({
        "ok": errors.is_empty(),
        "errors": errors,
        "warnings": warnings,
    })
}

/// Turns a JSON value into a structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A refusal, reported as a normal (structured) result rather than a protocol
/// error: the caller has to read the reason out to the human.
fn refusal(reason: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    ok(json!({
        "ok": false,
        "refused": true,
        "reason": reason.into(),
    }))
}
