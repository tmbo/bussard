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
//! Nothing here touches the bus. A model edit changes model files only; the
//! push to a device is `knx_plan_device` and `knx_apply_device` at the
//! programming tier. Every tool description says so, and every result carries
//! a `next_step` from [`crate::guidance`] that says how the edit reaches the
//! device at this server's tier, because the caller has to tell the human.
//!
//! Protected group addresses (`protected: true`) are refused outright, exactly
//! as `knx_write_group` refuses them: there is no MCP override, and no tool
//! parameter can set or clear the flag.

use std::path::Path;

use crate::args::Parameters;
use bussard_model::change::{ChangeKind, ChangeSet, describe, name_parameters};
use bussard_model::history::{History, SnapshotReason};
use bussard_model::param_model::{ProductModels, key_to_param_id};
use bussard_model::schema::{Group, Link, Location};
use bussard_model::{Dpt, GroupAddress, IndividualAddress, Model, Severity};
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::param_keys::{
    KeyContext, index_parameter, replace_parameter, resolve_parameter_key, unreached_refusal,
};
use crate::server::BussardMcp;
use crate::session_edits::Subject;

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
    /// KNX Data Secure for this group address. `false` removes its group key
    /// from the key store and clears the `secure` flag of the group and of
    /// every com-object linked to it on every device; `true` sets them and
    /// keeps the key the store has, or generates a new random key as ETS
    /// does. Omit it to leave security as it is.
    #[serde(default)]
    pub secure: Option<bool>,
}

/// Arguments for `knx_add_link` and `knx_remove_link`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LinkArgs {
    // The Claude remote-devices bridge reserves the key `device` for its own
    // routing and strips it from forwarded calls, so the field is `address`
    // and no other name is accepted.
    /// The device's individual address, e.g. `"1.1.4"`.
    pub address: String,
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
    /// The parameter key as `knx_show_device` lists it (`"betriebsart"`,
    /// page-qualified `"sollwerte.komfort"`, escape hatch
    /// `"nachtabsenkung@P-1312_R-2140"`), the same key prefixed with its page
    /// or channel handle (`"universalkanal-c4-funktion.helligkeitsschwelle"`),
    /// `key@reference`, or the bare reference (`"P-1312_R-2140"`).
    pub parameter: String,
    /// The channel handle (`"a-1"`), `"device"`, or the ETS page handle
    /// (`"universalkanal-c4-funktion"`) the parameter sits on, when the key
    /// alone is not unique on the device.
    #[serde(default)]
    pub channel: Option<String>,
    /// The new value: an enum label (`"Jalousie"`) or code, a number, or text.
    pub value: String,
    /// Store the value even though the configuration does not show the
    /// parameter under the device's current values (its page is inactive,
    /// or it belongs to another branch of a choice). Such a value is never
    /// written until the configuration shows it; use this only to prepare a
    /// branch before switching to it.
    #[serde(default)]
    pub force: bool,
}

/// Arguments for `knx_set_interface`. Every field but `address` is optional;
/// pass only what changes.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SetInterfaceArgs {
    /// The IP interface's individual address, e.g. `"1.1.200"`.
    pub address: String,
    /// How the interface gets its IP address: `"dhcp"` or `"static"`.
    /// Switching to `"dhcp"` drops the static address, netmask and gateway.
    #[serde(default)]
    pub assignment: Option<String>,
    /// The static IP address, e.g. `"192.168.1.80"` (`"static"` only).
    #[serde(default)]
    pub ip_address: Option<String>,
    /// The static netmask, e.g. `"255.255.255.0"` (`"static"` only).
    #[serde(default)]
    pub netmask: Option<String>,
    /// The static default gateway, e.g. `"192.168.1.1"`; `""` removes it.
    #[serde(default)]
    pub default_gateway: Option<String>,
    /// The friendly name, at most 30 ISO 8859-1 characters; `""` removes it
    /// from the table (the device keeps the name it has).
    #[serde(default)]
    pub friendly_name: Option<String>,
    /// The whole list of tunnelling addresses, in slot order, replacing the
    /// current one.
    #[serde(default)]
    pub tunnels: Option<Vec<String>>,
    /// Tunnelling addresses to append (one already listed is kept where it is).
    #[serde(default)]
    pub add_tunnels: Vec<String>,
    /// Tunnelling addresses to remove.
    #[serde(default)]
    pub remove_tunnels: Vec<String>,
}

/// Arguments for `knx_remove_group`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveGroupArgs {
    /// The group address to remove from groups.toml, e.g. `"1/0/22"`.
    pub ga: String,
}

/// Arguments for `knx_discard_edits`. Pass exactly one of `address` and
/// `group`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DiscardEditsArgs {
    // `address`, not `device`: the remote-devices bridge strips `device`.
    /// A device's individual address, e.g. `"1.1.5"`: drop its unapplied link
    /// and parameter edits.
    #[serde(default)]
    pub address: Option<String>,
    /// A group address, e.g. `"1/0/22"`: drop this session's edits of its
    /// groups.toml entry.
    #[serde(default)]
    pub group: Option<String>,
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
pub const MODEL_EDIT_TOOLS: [&str; 11] = [
    "knx_scaffold_groups",
    "knx_reserve_groups",
    "knx_set_group",
    "knx_remove_group",
    "knx_add_link",
    "knx_remove_link",
    "knx_set_device",
    "knx_set_parameter",
    "knx_set_interface",
    "knx_undo",
    "knx_discard_edits",
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
        \"Rocker 1 on Hallway push button (1.1.5) now switches Porch light (0/0/4).\" With no arguments it \
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

        let mut changes = describe(&from_model, &to_model);
        settle_changes(&dir, &mut changes, [&to_model, &from_model]);
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

        let summaries = history.summaries(&snapshots, start..snapshots.len());

        let mut rows = Vec::new();
        for ((index, snapshot), summary) in snapshots.iter().enumerate().skip(start).zip(summaries)
        {
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
        and free-text note. Creating one needs a name. This edits FILES ONLY: no telegram is sent, \
        and no device stores a group address's name or type; links that use it are pushed per \
        device with knx_plan_device and knx_apply_device. A group \
        address marked protected (safety-critical, e.g. a wind alarm) cannot be renamed or retyped \
        here, and there is deliberately no way to set or clear that flag over MCP. `secure` \
        switches KNX Data Secure for the group address: false removes its group key from the key \
        store (bussard.keys) and clears the secure flag of the group and of every linked \
        com-object on every device, true sets them and generates a group key when the store has \
        none; one change, undone with knx_undo. The Secure devices linked to it then need \
        knx_plan_device and knx_apply_device (their security object changes), and Home Assistant \
        and every other keyring user need a new `bussard keys export`. Returns the change as \
        sentences: quote them to the human."
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
        let summary = match args.secure {
            Some(secure) => format!("{ga} secure={secure}"),
            None => format!("{ga}"),
        };
        if let Some(secure) = args.secure {
            return self.set_group_secure(ga, secure, name, dpt, description, summary);
        }

        self.edit("knx_set_group", vec![summary], move |model| {
            edit_group_fields(model, ga, name, dpt, description)
        })
    }

    /// `knx_remove_group`.
    #[tool(
        description = "Remove a group address from groups.toml. Refused while any com object \
        still sends or listens to it: the refusal lists those links, and knx_remove_link unbinds \
        each one first. A protected group address (safety-critical, e.g. a wind alarm) is \
        refused outright. This edits FILES ONLY: no telegram is sent and no device stores a \
        group address's name; knx_undo puts it back. Returns the change as sentences: quote \
        them to the human."
    )]
    async fn knx_remove_group(
        &self,
        Parameters(args): Parameters<RemoveGroupArgs>,
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
        self.edit("knx_remove_group", vec![ga.to_string()], move |model| {
            let Some(group) = model.groups.groups.get(&ga) else {
                return Err(format!(
                    "{ga} is not in groups.toml, so there is nothing to remove"
                ));
            };
            if group.protected {
                return Err(format!(
                    "{ga} ({:?}) is protected (safety-critical): removing it is refused over MCP. \
                     A human can edit groups.toml directly.",
                    group.name
                ));
            }
            let users = links_using(model, ga);
            if !users.is_empty() {
                return Err(format!(
                    "{ga} ({:?}) is still linked: {}. Unbind each with knx_remove_link first, \
                     then remove the group address.",
                    group.name,
                    users.join("; ")
                ));
            }
            model.groups.groups.remove(&ga);
            Ok(())
        })
    }

    /// `knx_add_link`.
    #[tool(
        description = "Bind a device's com object to a group address in its device file (devices/<address>.toml). The device's individual address goes in `address` (e.g. \"1.1.4\"). Role \"send\" \
        makes the com object transmit on that GA (a com object has at most one, so an existing one \
        is replaced), role \"listen\" makes it react to the GA. A GA that groups.toml does not \
        define yet is added there, named `<channel or device name> <object function>` with the \
        object's DPT, and reported in groups_declared. This edits FILES ONLY: the device \
        keeps its current wiring until knx_plan_device and knx_apply_device push it (the \
        result's next_step says how at this server's tier). Protected group addresses are refused outright. \
        A link that puts a device without KNX Data Secure on a group address the other side runs \
        secured (validation E035/E036) is refused with the ways out. Returns the change as sentences: quote \
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
            let insecure_before = bussard_model::secure_link_conflicts(model);
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
            refuse_new_insecure_link(&insecure_before, model, ga)
        })
    }

    /// `knx_remove_link`.
    #[tool(
        description = "Unbind a device's com object from a group address in its device file (devices/<address>.toml) (role \
        \"send\" or \"listen\"). The device's individual address goes in `address` (e.g. \"1.1.4\"). This edits FILES ONLY: the device keeps its current wiring until \
        knx_plan_device and knx_apply_device push it (the result's next_step says how at this \
        server's tier). Protected group addresses are \
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
        (e.g. a night setback temperature). `parameter` is the key knx_show_device lists \
        (`helligkeitsschwelle`, page-qualified `sollwerte.komfort`, or `key@reference`); the \
        same key prefixed with its page or channel handle \
        (`universalkanal-c4-funktion.helligkeitsschwelle`) and the bare reference \
        (`P-7305_R-7305`) work too, and `channel` takes a channel handle, `device` or a page \
        handle, as knx_show_device does, when the key repeats. An unknown key is refused with \
        the three closest keys on the device. Any \
        parameter the lock knows for the device, or the product model's pages hold (one on a \
        page that was inactive at import), can be set, and the value (an enum label or \
        code, a number) is checked against the vendor's product model first; without a product \
        model the edit is refused rather than guessed. This edits FILES ONLY: the device keeps \
        its current settings until the change is pushed with knx_plan_device and \
        knx_apply_device (the plan lists the parameter by name); the result's next_step says how \
        it reaches the device at this server's tier. Parameters at their vendor default are set \
        the same way. A parameter that shows or hides com-objects (an enable flag, a data \
        length) changes the group-object table, which only a full download writes: the \
        result's `note` names the objects and how that download is pushed at this server's \
        tier (with --allow-programming, knx_plan_device plans it as `method: flash`), and \
        knx_show_device lists the parameters and objects it reveals right away. A parameter \
        the configuration does not show under the device's current values (its page is \
        inactive, or it belongs to another branch of a choice) is refused with the condition \
        that shows it and the ref that is shown instead, because the device would never get \
        the value; `force: true` stores it anyway to prepare a branch before switching to it. \
        A bare parameter id (`P-7305`) or the vendor text names the ref the configuration \
        shows. Returns the change as sentences: quote them to the human."
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
        let force = args.force;
        let label = vec![ia.to_string(), wanted.clone(), value.clone()];

        let tiers = crate::guidance::Tiers::of(self.state());
        self.edit_with_note("knx_set_parameter", label, move |model| {
            let app = model
                .devices
                .get(&ia)
                .and_then(|d| d.device.product.as_ref())
                .and_then(|p| p.application_ref.clone());
            let products = ProductModels::load_apps(&dir, app.iter().map(String::as_str));
            let keys = KeyContext::new(model, &products, ia);
            let Some(loaded) = model.devices.get_mut(&ia) else {
                return Err(format!("{ia} is not a device in this model"));
            };
            let key = resolve_parameter_key(&loaded.device, &keys, &wanted, channel.as_deref())?;
            // Issue #321: a value on a ref the configuration does not show is
            // never written, so it is refused unless the caller prepares a
            // branch on purpose.
            if !force && let Some(why) = unreached_refusal(&loaded.device, &keys, &key) {
                return Err(why);
            }
            let value = check_parameter(&dir, loaded, &key, &value)?;
            // A parameter on a page that was inactive at import gets its lock
            // entry now, saved with the device file below.
            index_parameter(&mut loaded.device, &keys, &key);
            replace_parameter(&mut loaded.device, &key, value);
            Ok(refresh_device_facts(&dir, model, ia, tiers))
        })
    }

    /// `knx_set_interface`.
    #[tool(
        description = "Edit the [knxnet] table of a KNX IP interface's device file \
        (devices/<address>.toml): how it gets its IP address (assignment `dhcp` or `static`, \
        with ip_address, netmask and default_gateway for static), its friendly name, and its \
        tunnelling addresses (tunnels replaces the list; add_tunnels and remove_tunnels change \
        it). Pass only what changes. The table is validated before it is saved: a static \
        assignment needs an address and a netmask, static settings under dhcp, a friendly name \
        over 30 ISO 8859-1 characters, a tunnel address listed twice, off the interface's line \
        or used by a device of the model are refused (E043 to E046), and the result's \
        `warnings` carry W047 when the tunnels differ from the ones the server's keyring lists \
        for the interface. The device must already have a [knxnet] table (import and adopt \
        write it). This edits FILES ONLY: knx_plan_device shows the property writes and \
        knx_apply_device writes them to the interface's KNXnet/IP parameter object; a change of \
        the IP assignment, address or tunnel addresses of the interface this server tunnels \
        through is refused there (the owner applies it with `bussard apply <address> --allow-self-reconfigure`). \
        Returns the change as sentences: quote them to the human."
    )]
    async fn knx_set_interface(
        &self,
        Parameters(args): Parameters<SetInterfaceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ia: IndividualAddress = match args.address.parse() {
            Ok(ia) => ia,
            Err(_) => {
                return refusal(format!(
                    "{:?} is not an individual address like \"1.1.200\"",
                    args.address
                ));
            }
        };
        if args.assignment.is_none()
            && args.ip_address.is_none()
            && args.netmask.is_none()
            && args.default_gateway.is_none()
            && args.friendly_name.is_none()
            && args.tunnels.is_none()
            && args.add_tunnels.is_empty()
            && args.remove_tunnels.is_empty()
        {
            return refusal(
                "nothing to change: pass at least one of assignment, ip_address, netmask, \
                 default_gateway, friendly_name, tunnels, add_tunnels or remove_tunnels",
            );
        }
        let keyring = self.state().keyring.clone();
        self.edit_with_note("knx_set_interface", vec![ia.to_string()], move |model| {
            let devices: Vec<IndividualAddress> = model.devices.keys().copied().collect();
            let Some(loaded) = model.devices.get_mut(&ia) else {
                return Err(format!("{ia} is not a device in this model"));
            };
            let Some(table) = loaded.device.knxnet.as_mut() else {
                return Err(format!(
                    "devices/{ia}.toml has no [knxnet] table: {ia} is not modelled as a KNX IP \
                     interface (import the project or adopt the interface to write one)"
                ));
            };
            set_interface(table, &args)?;
            let issues = bussard_model::knxnet::check_config(ia, table, &devices);
            if !issues.is_empty() {
                let lines: Vec<String> = issues
                    .iter()
                    .map(|i| format!("{}: {}", i.code, i.message))
                    .collect();
                return Err(format!(
                    "the [knxnet] table of {ia} would not validate, nothing was written: {}",
                    lines.join("; ")
                ));
            }
            let facts = keyring
                .as_deref()
                .map(|path| bussard_service::secure::keyring_facts(path, "the server's keyring"));
            let warnings: Vec<String> =
                bussard_service::admission::knxnet_tunnel_keyring_diagnostics(
                    model,
                    facts.as_ref(),
                )
                .into_iter()
                .filter(|d| d.location.starts_with(&format!("devices/{ia}.toml")))
                .map(|d| format!("{}: {}", d.code, d.message))
                .collect();
            Ok((!warnings.is_empty()).then(|| warnings.join(" ")))
        })
    }

    /// `knx_undo`.
    #[tool(
        description = "Put the model files back to a history snapshot (default: the newest \
        snapshot that differs from the current files, i.e. undo the last change). This changes FILES ONLY: devices keep whatever is in their tables until \
        knx_plan_device and knx_apply_device push them (the result's next_step names the \
        devices and says how at this server's tier). The state before the undo is \
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
        let mut changes = before
            .as_ref()
            .map(|b| describe(b, &restored))
            .unwrap_or_default();
        if let Some(b) = &before {
            settle_changes(&dir, &mut changes, [&restored, b]);
        }

        let undo_snapshot = match history.restore(&target.id) {
            Ok(id) => id,
            Err(err) => return refusal(format!("the restore failed: {err}")),
        };
        // A group address whose Data Secure state the undo flips gets its
        // key back from the snapshot's key store copy, or loses it (#331).
        let key_store = match &before {
            Some(b)
                if !bussard_service::group_security::security_changes(b, &restored).is_empty() =>
            {
                let password =
                    bussard_model::dotenv::var(bussard_service::secure::KEYRING_PASSWORD_ENV).ok();
                Some(
                    match bussard_service::group_security::restore_group_keys(
                        &dir,
                        &history.snapshot_dir(&target.id),
                        Some(&history.snapshot_dir(&undo_snapshot)),
                        b,
                        &restored,
                        password.as_deref(),
                    ) {
                        Ok(notes) => json!({"ok": true, "sentences": notes}),
                        Err(err) => json!({
                            "ok": false,
                            "reason": format!(
                                "the model files are restored, but the key store did not \
                                 follow: {err}. Fix that and run `bussard groups secure` for \
                                 the group addresses whose security the undo changed."
                            ),
                        }),
                    },
                )
            }
            _ => None,
        };
        self.state().model.reload();
        self.session_edits()
            .undone(target.id.as_str(), undo_snapshot.as_str(), &changes);

        let earlier = before
            .as_ref()
            .map(|b| bussard_model::validate_in_dir(b, &dir))
            .unwrap_or_default();
        let diagnostics = bussard_model::validate_in_dir(&restored, &dir);
        let mut result = json!({
            "ok": true,
            "restored": target.id,
            "snapshot": undo_snapshot,
            "validation": validation_json(&earlier, &diagnostics),
            "next_step": self.next_step(&changes),
        });
        put_changes(&mut result, &changes);
        if let (Some(key_store), Some(map)) = (key_store, result.as_object_mut()) {
            map.insert("key_store".to_string(), key_store);
        }
        ok(result)
    }

    /// `knx_discard_edits`.
    #[tool(
        description = "Abandon this session's unapplied edits of ONE subject and leave every \
        other edit alone: `address` (a device: its link and parameter edits since it last \
        matched the model) or `group` (a group address: its groups.toml edits). The subject's \
        part of the files goes back to the snapshot before its first such edit. Use it to \
        revert one device while edits on other devices stay; knx_undo instead rolls the whole \
        model back to a snapshot. A group created this session that a link still uses cannot \
        be discarded (the refusal lists the links; knx_remove_link first). A group whose Data \
        Secure state the discard flips gets its group key back in the key store, or loses it, \
        as knx_undo does (`key_store`). This edits FILES \
        ONLY and snapshots first, so knx_undo brings the edits back. Returns the dropped edits \
        as sentences: quote them to the human."
    )]
    async fn knx_discard_edits(
        &self,
        Parameters(args): Parameters<DiscardEditsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if self.state().no_model_edits {
            return refusal("this server was started with --no-model-edits");
        }
        let subject = match (args.address.as_deref(), args.group.as_deref()) {
            (Some(raw), None) => match raw.parse::<IndividualAddress>() {
                Ok(ia) => Subject::Device(ia),
                Err(_) => {
                    return refusal(format!(
                        "{raw:?} is not an individual address like \"1.1.4\""
                    ));
                }
            },
            (None, Some(raw)) => match raw.parse::<GroupAddress>() {
                Ok(ga) => Subject::Group(ga),
                Err(_) => {
                    return refusal(format!("{raw:?} is not a group address like \"0/0/4\""));
                }
            },
            _ => {
                return refusal(
                    "pass exactly one of `address` (a device) or `group` (a group address)",
                );
            }
        };
        let pending = self.session_edits().pending(subject);
        let Some(baseline) = pending.iter().map(|e| e.snapshot.clone()).min() else {
            return refusal(format!(
                "this session has no unapplied edits of {subject}, so there is nothing to \
                 discard. knx_undo rolls the whole model back to a snapshot."
            ));
        };

        let dir = self.state().dir.clone();
        let history = History::open(&dir);
        let before = match Model::load(&dir) {
            Ok(model) => model,
            Err(err) => {
                return refusal(format!(
                    "the model at {} does not load: {err}",
                    dir.display()
                ));
            }
        };
        let (base_id, base) = match history
            .resolve(&baseline)
            .and_then(|snapshot| history.load(&snapshot.id).map(|model| (snapshot.id, model)))
        {
            Ok(found) => found,
            Err(err) => return refusal(format!("snapshot {baseline} does not load: {err}")),
        };
        let mut edited = before.clone();
        let mut notes: Vec<String> = Vec::new();
        match subject {
            Subject::Device(ia) => {
                let Some(device) = base.devices.get(&ia) else {
                    return refusal(format!(
                        "{ia} is not in snapshot {baseline}, so its edits cannot be discarded \
                         here; knx_undo rolls the whole model back"
                    ));
                };
                edited.devices.insert(ia, device.clone());
                match base.links.links.get(&ia) {
                    Some(links) => {
                        edited.links.links.insert(ia, links.clone());
                    }
                    None => {
                        edited.links.links.remove(&ia);
                    }
                }
                // A group address a dropped link used and this session
                // created stays in groups.toml: say so.
                let gas_of = |model: &Model| -> std::collections::BTreeSet<GroupAddress> {
                    model
                        .links
                        .links
                        .get(&ia)
                        .into_iter()
                        .flatten()
                        .flat_map(|l| l.send.into_iter().chain(l.listen.iter().copied()))
                        .collect()
                };
                let kept = gas_of(&base);
                let session_groups: Vec<GroupAddress> = gas_of(&before)
                    .into_iter()
                    .filter(|ga| !kept.contains(ga) && before.groups.groups.contains_key(ga))
                    .filter(|ga| self.created_in_session(&history, *ga))
                    .collect();
                for ga in session_groups {
                    notes.push(format!(
                        "Group address {ga} was created in this session and stays in \
                         groups.toml; knx_discard_edits with group {ga} or knx_remove_group \
                         drops it once nothing links it."
                    ));
                }
            }
            Subject::Group(ga) => match base.groups.groups.get(&ga) {
                Some(group) => {
                    edited.groups.groups.insert(ga, group.clone());
                }
                None => {
                    let users = links_using(&before, ga);
                    if !users.is_empty() {
                        return refusal(format!(
                            "{ga} was created in this session and is still linked: {}. \
                             Discarding it would leave those links without a group address; \
                             unbind them with knx_remove_link (or knx_discard_edits on each \
                             device) first.",
                            users.join("; ")
                        ));
                    }
                    edited.groups.groups.remove(&ga);
                }
            },
        }

        let mut changes = describe(&before, &edited);
        settle_changes(&dir, &mut changes, [&edited, &before]);
        let dropped_sentences: Vec<String> = pending
            .iter()
            .flat_map(|e| e.sentences.iter().cloned())
            .collect();
        if changes.is_empty() {
            // The files already say what the baseline said (a human reverted
            // them): only the record goes.
            self.session_edits().discard(subject, None);
            return ok(json!({
                "ok": true,
                "discarded": subject.to_string(),
                "dropped": dropped_sentences,
                "changes": [],
                "note": "the files already matched the state before these edits; nothing was written",
            }));
        }

        let reason = SnapshotReason::new("mcp knx_discard_edits")
            .with_args(vec![subject.to_string()])
            .with_result("before discarding a subject's edits");
        let snapshot = match history.snapshot(reason) {
            Ok(id) => id,
            Err(err) => {
                return refusal(format!(
                    "refusing to discard: the history snapshot could not be written ({err})"
                ));
            }
        };
        if let Err(err) = edited.save(&dir) {
            return refusal(format!("the model could not be saved: {err}"));
        }
        // A group address whose Data Secure state the discard flips gets its
        // key back from the baseline snapshot's key store copy, or loses it,
        // exactly as knx_undo does (#331, #336). The discard's own snapshot
        // keeps the current store, so an undo of the discard restores it.
        let key_store = (!bussard_service::group_security::security_changes(&before, &edited)
            .is_empty())
        .then(|| {
            let password =
                bussard_model::dotenv::var(bussard_service::secure::KEYRING_PASSWORD_ENV).ok();
            match bussard_service::group_security::restore_group_keys(
                &dir,
                &history.snapshot_dir(&base_id),
                Some(&history.snapshot_dir(&snapshot)),
                &before,
                &edited,
                password.as_deref(),
            ) {
                Ok(notes) => json!({"ok": true, "sentences": notes}),
                Err(err) => json!({
                    "ok": false,
                    "reason": format!(
                        "the model files are restored, but the key store did not follow: \
                         {err}. Fix that and run `bussard groups secure` for the group \
                         addresses whose security the discard changed."
                    ),
                }),
            }
        });
        self.state().model.reload();
        self.session_edits()
            .discard(subject, Some(snapshot.as_str()));

        let earlier = bussard_model::validate_in_dir(&before, &dir);
        let diagnostics = bussard_model::validate_in_dir(&edited, &dir);
        let next_step = match subject {
            Subject::Device(ia) if self.state().programming.is_some() && !self.state().passive => {
                format!(
                    "{ia}'s file is back to what it was before these edits. If the device \
                     received none of them, it already matches; knx_plan_device for {ia} \
                     confirms it."
                )
            }
            _ => self.next_step(&changes),
        };
        let mut result = json!({
            "ok": true,
            "discarded": subject.to_string(),
            "dropped": dropped_sentences,
            "snapshot": snapshot,
            "touches_protected": changes.touches_protected(),
            "validation": validation_json(&earlier, &diagnostics),
            "next_step": next_step,
        });
        put_changes(&mut result, &changes);
        if let (false, Some(map)) = (notes.is_empty(), result.as_object_mut()) {
            map.insert("note".to_string(), Value::String(notes.join(" ")));
        }
        if let (Some(key_store), Some(map)) = (key_store, result.as_object_mut()) {
            map.insert("key_store".to_string(), key_store);
        }
        ok(result)
    }
}

impl BussardMcp {
    /// Whether this session created `ga`: it has session edits, and the
    /// snapshot before the first of them does not define it.
    fn created_in_session(&self, history: &History, ga: GroupAddress) -> bool {
        let Some(first) = self
            .session_edits()
            .pending(Subject::Group(ga))
            .into_iter()
            .map(|e| e.snapshot)
            .min()
        else {
            return false;
        };
        history
            .resolve(&first)
            .and_then(|snapshot| history.load(&snapshot.id))
            .is_ok_and(|model| !model.groups.groups.contains_key(&ga))
    }

    /// The `next_step` for an edit that produced `changes`, at this server's
    /// tier (see [`crate::guidance::Tiers::next_step`]).
    fn next_step(&self, changes: &ChangeSet) -> String {
        crate::guidance::next_step(self.state(), changes)
    }

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
        self.edit_with_note(tool, args, |model| apply(model).map(|()| None))
    }

    /// [`Self::edit`] for an edit that may add a `note` to its result (what
    /// a parameter change revealed or hid, and that it needs a flash).
    fn edit_with_note<F>(
        &self,
        tool: &str,
        args: Vec<String>,
        apply: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(&mut Model) -> Result<Option<String>, String>,
    {
        self.edit_with_hook(tool, args, apply, None)
    }

    /// [`Self::edit_with_note`] with a step that runs after the history
    /// snapshot and before the model files are saved (issue #331: the key
    /// store copy and write of a security change). The hook gets the
    /// snapshot directory and returns extra result fields; its refusal
    /// leaves the model files untouched. With a hook the ladder runs even
    /// when the model files would not change, since the hook may.
    fn edit_with_hook<F>(
        &self,
        tool: &str,
        args: Vec<String>,
        apply: F,
        hook: Option<SnapshotHook<'_>>,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(&mut Model) -> Result<Option<String>, String>,
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
        let note = match apply(&mut edited) {
            Ok(note) => note,
            Err(reason) => return refusal(reason),
        };
        // A group address the edit links but groups.toml does not define is
        // declared there, named after the object that uses it first; the
        // change set below reports it with the rest.
        let declared: Vec<String> = bussard_model::declare_used_groups(&mut edited)
            .iter()
            .map(|d| d.sentence())
            .collect();
        let mut changes = describe(&before, &edited);
        settle_changes(&dir, &mut changes, [&edited, &before]);
        if changes.is_empty() && hook.is_none() {
            return ok(json!({
                "ok": true,
                "changes": [],
                "note": "the model already said that; nothing was written",
            }));
        }

        let reason = SnapshotReason::new(format!("mcp {tool}"))
            .with_args(args)
            .with_result("before an MCP model edit");
        let history = History::open(&dir);
        let snapshot = match history.snapshot(reason) {
            Ok(id) => id,
            Err(err) => {
                return refusal(format!(
                    "refusing to edit: the history snapshot could not be written ({err})"
                ));
            }
        };
        let extra = match hook {
            Some(hook) => match hook(&history.snapshot_dir(&snapshot)) {
                Ok(extra) => extra,
                Err(reason) => return refusal(reason),
            },
            None => serde_json::Map::new(),
        };

        if let Err(err) = edited.save(&dir) {
            return refusal(format!("the model could not be saved: {err}"));
        }
        // The handle debounces its directory check; force it so the very next
        // tool call sees what we just wrote.
        self.state().model.reload();

        self.session_edits()
            .record(snapshot.as_str(), tool, &changes);

        let earlier = bussard_model::validate_in_dir(&before, &dir);
        let diagnostics = bussard_model::validate_in_dir(&edited, &dir);
        let mut result = json!({
            "ok": true,
            "snapshot": snapshot,
            "touches_protected": changes.touches_protected(),
            "groups_declared": declared,
            "validation": validation_json(&earlier, &diagnostics),
            "next_step": self.next_step(&changes),
        });
        put_changes(&mut result, &changes);
        if let Some(map) = result.as_object_mut() {
            if let Some(note) = note {
                map.insert("note".to_string(), Value::String(note));
            }
            map.extend(extra);
        }
        ok(result)
    }

    /// `knx_set_group` with `secure` (issue #331): the group's and every
    /// linked com-object's `secure` flag in the model, and the group key in
    /// the key store, as one change with one snapshot (which keeps a copy of
    /// the key store, so `knx_undo` restores all three).
    fn set_group_secure(
        &self,
        ga: GroupAddress,
        secure: bool,
        name: Option<String>,
        dpt: Option<Dpt>,
        description: Option<String>,
        summary: String,
    ) -> Result<CallToolResult, ErrorData> {
        use bussard_service::group_security as gs;
        if self.state().no_model_edits {
            return refusal("this server was started with --no-model-edits");
        }
        let dir = self.state().dir.clone();
        let store_path = bussard_project::KeyStore::path(&dir);
        // The key store is the only key source this edit changes: a server
        // reading another keyring would keep securing the group address.
        if let Some(keyring) = &self.state().keyring
            && !same_file(keyring, &store_path)
        {
            return refusal(format!(
                "this server reads its keys from {}, not from the key store {}: switching Data                  Secure for {ga} changes the key store only. Import that keyring with `bussard                  keys import`, then restart the server without --keyring.",
                keyring.display(),
                store_path.display()
            ));
        }
        let password =
            bussard_model::dotenv::var(bussard_service::secure::KEYRING_PASSWORD_ENV).ok();
        // Fail before anything is written when the store cannot be changed.
        if let Err(err) = gs::load_store(&dir, password.as_deref()) {
            return refusal(format!("{err}; nothing was changed"));
        }
        let protected = Model::load(&dir)
            .ok()
            .is_some_and(|m| model_groups_protected(&m.groups, ga));
        if protected {
            return refusal(format!(
                "{ga} is protected: switching its Data Secure state is refused over MCP. A human \
                 can run `bussard groups secure {ga} {}` from the CLI.",
                if secure { "on" } else { "off" }
            ));
        }
        let edited: std::cell::RefCell<Option<gs::GroupSecurityEdit>> = Default::default();
        let devices_note = std::cell::RefCell::new(String::new());
        let apply = |model: &mut Model| -> Result<Option<String>, String> {
            edit_group_fields(model, ga, name, dpt, description)?;
            let edit = gs::edit_model(model, ga, secure)?;
            let devices = edit.secure_devices(model);
            *devices_note.borrow_mut() = if devices.is_empty() {
                String::new()
            } else {
                let list: Vec<String> = devices.iter().map(ToString::to_string).collect();
                format!(
                    " The security object of {} changes: plan and apply {} to remove or add \
                     the group key table entry (PID 53) and the objects' security flags \
                     (PID 61).",
                    list.join(", "),
                    if devices.len() == 1 { "it" } else { "each" }
                )
            };
            *edited.borrow_mut() = Some(edit);
            Ok(Some(format!(
                "{}{}",
                gs::export_note(ga, secure),
                devices_note.borrow()
            )))
        };
        let hook_dir = dir.clone();
        let hook: SnapshotHook<'_> = Box::new(move |snapshot_dir: &Path| {
            let mut store = gs::load_store(&hook_dir, password.as_deref())
                .map_err(|e| format!("{e}; nothing was changed"))?;
            let kept = gs::keep_keystore(&hook_dir, snapshot_dir)
                .map_err(|e| format!("{e}; nothing was changed"))?;
            let action = gs::apply_group_key(&mut store, ga, secure)
                .map_err(|e| format!("{e}; nothing was changed"))?;
            if action.changed() {
                let password = password.as_deref().unwrap_or_default();
                gs::save_store(&hook_dir, &store, password)
                    .map_err(|e| format!("{e}; nothing was changed"))?;
            }
            let mut extra = serde_json::Map::new();
            extra.insert(
                "key_store".to_string(),
                json!({
                    "group_key": action.label(),
                    "sentence": action.sentence(ga),
                    "snapshot_keeps_key_store": kept,
                    "export_needed": true,
                }),
            );
            Ok(extra)
        });
        let mut result = self.edit_with_hook("knx_set_group", vec![summary], apply, Some(hook));
        if let (Ok(call), Some(edit)) = (&mut result, edited.borrow().as_ref()) {
            let devices: Vec<Value> = edit
                .devices
                .iter()
                .map(|(ia, objects)| json!({"address": ia.to_string(), "objects": objects}))
                .collect();
            if let Some(Value::Object(map)) = call.structured_content.as_mut()
                && map.get("ok") == Some(&Value::Bool(true))
            {
                map.insert(
                    "security".to_string(),
                    json!({"ga": ga.to_string(), "secure": secure, "devices": devices}),
                );
            }
        }
        result
    }
}

/// A step of [`BussardMcp::edit_with_hook`] that runs on the snapshot
/// directory and returns extra result fields.
type SnapshotHook<'a> =
    Box<dyn FnOnce(&Path) -> Result<serde_json::Map<String, Value>, String> + 'a>;

/// Whether two paths name the same file (canonical paths, else as given).
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Re-derives the lock-side facts of `ia` (channels, objects, the parameter
/// index) with its device file's current values, when the lock pins an
/// intact product archive for it (issue #276). A parameter that enables a
/// block or picks a data length then shows its dependent parameters and
/// objects in `knx_show_device` right away. Returns a note naming the
/// objects the change shows or hides, which only a full flash writes, and
/// how that flash is pushed at `tiers` (issue #303); `None`
/// when nothing changed shape or there is no archive to derive from.
fn refresh_device_facts(
    dir: &Path,
    model: &mut Model,
    ia: IndividualAddress,
    tiers: crate::guidance::Tiers,
) -> Option<String> {
    let lookup = bussard_service::params::resolve_product(
        dir,
        bussard_service::params::Selection::default(),
        Some(model),
        ia,
        bussard_service::params::MissingProduct::Warn,
        None,
    )
    .ok()?;
    let source = lookup.source?;
    let app = source.app()?;
    let linked: std::collections::BTreeSet<u16> = model
        .links
        .links
        .get(&ia)
        .map(|links| links.iter().map(|l| l.object).collect())
        .unwrap_or_default();
    let device = &mut model.devices.get_mut(&ia)?.device;
    let values: std::collections::BTreeMap<String, String> = device
        .parameters
        .iter()
        .filter_map(|(k, v)| Some((k.split_once('@')?.1.to_string(), v.clone())))
        .collect();
    let facts = bussard_project::facts::derive_facts(app, &values, &Default::default());
    let shape =
        |d: &bussard_model::schema::Device| -> std::collections::BTreeMap<u16, Option<String>> {
            d.com_objects
                .iter()
                .map(|(n, o)| (*n, o.reference.clone()))
                .collect()
        };
    let before = shape(device);
    bussard_project::facts::refresh_facts(device, &facts, &linked);
    let after = shape(device);
    let list = |numbers: Vec<&u16>| {
        numbers
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let shown: Vec<&u16> = after.keys().filter(|n| !before.contains_key(n)).collect();
    let hidden: Vec<&u16> = before.keys().filter(|n| !after.contains_key(n)).collect();
    let resized: Vec<&u16> = after
        .iter()
        .filter(|(n, r)| before.get(n).is_some_and(|b| b != *r))
        .map(|(n, _)| n)
        .collect();
    let mut parts = Vec::new();
    if !shown.is_empty() {
        parts.push(format!("shows object(s) {}", list(shown)));
    }
    if !hidden.is_empty() {
        parts.push(format!("hides object(s) {}", list(hidden)));
    }
    if !resized.is_empty() {
        parts.push(format!(
            "changes the size or flags of object(s) {}",
            list(resized)
        ));
    }
    (!parts.is_empty()).then(|| {
        format!(
            "This value {} on {ia}; knx_show_device lists the device under it. {}",
            parts.join(", "),
            tiers.flash_push(Some(ia))
        )
    })
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

/// The name, type and note half of `knx_set_group`: creates the group address
/// or updates its fields, refusing to rename or retype a protected one.
fn edit_group_fields(
    model: &mut Model,
    ga: GroupAddress,
    name: Option<String>,
    dpt: Option<Dpt>,
    description: Option<String>,
) -> Result<(), String> {
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
}

/// Parses the shared link-tool arguments.
fn parse_link_args(args: &LinkArgs) -> Result<(IndividualAddress, GroupAddress, Role), String> {
    let ia: IndividualAddress = args.address.parse().map_err(|_| {
        format!(
            "{:?} is not an individual address like \"1.1.4\"",
            args.address
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

/// Every com object in `model` that sends or listens to `ga`, as
/// `1.1.5 object 3 listens` lines, by device and object.
fn links_using(model: &Model, ga: GroupAddress) -> Vec<String> {
    let mut out = Vec::new();
    for (ia, links) in &model.links.links {
        for link in links {
            if link.send == Some(ga) {
                out.push(format!("{ia} object {} sends", link.object));
            }
            if link.listen.contains(&ga) {
                out.push(format!("{ia} object {} listens", link.object));
            }
        }
    }
    out
}

/// Whether a GA is protected in `groups`.
fn model_groups_protected(groups: &bussard_model::schema::Groups, ga: GroupAddress) -> bool {
    groups.groups.get(&ga).is_some_and(|g| g.protected)
}

/// Refuses an edit that makes a device without Data Secure send on a group
/// address a receiver takes secured, or listen to one a Secure sender sends
/// secured (validation errors E035 and E036, issue #330). Only a conflict on
/// `ga` that `before` did not already have counts, so an old one elsewhere
/// does not block an unrelated link.
fn refuse_new_insecure_link(
    before: &[bussard_model::SecureLinkConflict],
    model: &Model,
    ga: GroupAddress,
) -> Result<(), String> {
    let same = |a: &bussard_model::SecureLinkConflict, b: &bussard_model::SecureLinkConflict| {
        a.kind == b.kind && a.device == b.device && a.object == b.object && a.ga == b.ga
    };
    let new: Vec<String> = bussard_model::secure_link_conflicts(model)
        .iter()
        .filter(|c| c.ga == ga && !before.iter().any(|b| same(b, c)))
        .map(|c| format!("{}: {}", c.code(), c.message()))
        .collect();
    if new.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "refused, the link would not work: {}",
            new.join("; ")
        ))
    }
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

/// The `{base, changes, sentences}` payload `knx_describe_change` returns.
fn change_json(base: Option<String>, changes: &ChangeSet) -> Value {
    let mut out = json!({
        "ok": true,
        "base": base,
        "count": changes.len(),
        "touches_protected": changes.touches_protected(),
        "note": "Nothing here has reached any device: these are model files only.",
    });
    let (sentences, detail, truncated) = capped(changes, MAX_DESCRIBED_CHANGES);
    if let Some(map) = out.as_object_mut() {
        map.insert("sentences".into(), json!(sentences));
        map.insert("changes".into(), json!(detail));
        if let Some(note) = truncated {
            map.insert("truncated".into(), json!(note));
        }
    }
    out
}

/// The most changes an edit or undo result lists (issue #279): a result the
/// client has to spill to a file helps nobody. `knx_describe_change` lists
/// up to [`MAX_DESCRIBED_CHANGES`].
pub const MAX_RESULT_CHANGES: usize = 50;

/// The most changes `knx_describe_change` lists.
pub const MAX_DESCRIBED_CHANGES: usize = 200;

/// The most diagnostics of one kind a `validation` object lists; the counts
/// stay exact and `knx_validate` lists them all.
pub const MAX_RESULT_DIAGNOSTICS: usize = 20;

/// The first `max` sentences and changes of `changes` (protected ones
/// first, as [`sentences`] orders them), and a note when some were left out.
fn capped(
    changes: &ChangeSet,
    max: usize,
) -> (Vec<String>, Vec<bussard_model::Change>, Option<String>) {
    let mut ordered: Vec<&bussard_model::Change> = changes.changes.iter().collect();
    ordered.sort_by_key(|c| !c.touches_protected);
    let total = ordered.len();
    let kept: Vec<bussard_model::Change> = ordered.into_iter().take(max).cloned().collect();
    let sentences = kept.iter().map(|c| c.sentence.clone()).collect();
    let note = (total > max).then(|| {
        format!(
            "showing {max} of {total} changes; knx_describe_change with this result's \
             snapshot as `from` lists them"
        )
    });
    (sentences, kept, note)
}

/// Puts `changes` into an edit or undo result as `changes` (sentences) and
/// `detail` (structured), capped at [`MAX_RESULT_CHANGES`] with a
/// `truncated` note.
fn put_changes(result: &mut Value, changes: &ChangeSet) {
    let (sentences, detail, truncated) = capped(changes, MAX_RESULT_CHANGES);
    if let Some(map) = result.as_object_mut() {
        map.insert("changes".into(), json!(sentences));
        map.insert("detail".into(), json!(detail));
        if let Some(note) = truncated {
            map.insert("truncated".into(), json!(note));
        }
    }
}

/// The `knxnet` section of `knx_show_device` for an IP interface (issue
/// #391): the device file's `[knxnet]` table (`model`), what the device's
/// KNXnet/IP parameter object last reported (`device`, from the device facts
/// `status` and `describe` keep, with its `read_at`), where the two differ
/// (`drift`) and how to change it. `None` for a device with neither.
pub(crate) fn knxnet_section(dir: &Path, model: &Model, ia: IndividualAddress) -> Option<Value> {
    let config = model.devices.get(&ia).and_then(|d| d.device.knxnet.clone());
    let facts = bussard_model::facts::load_facts(dir, ia)
        .ok()
        .flatten()
        .and_then(|r| r.knxnet);
    if config.is_none() && facts.is_none() {
        return None;
    }
    let drift = match (&facts, &config) {
        (Some(f), Some(c)) => f.drift(c),
        _ => Vec::new(),
    };
    Some(json!({
        "model": config,
        "device": facts,
        "drift": drift,
        "how_to_change": format!(
            "The KNXnet/IP settings live in the [knxnet] table of devices/{ia}.toml \
             (assignment, address, netmask, gateway, friendly_name, tunnels); \
             knx_set_interface edits them (knx_set_parameter does not), and \
             knx_plan_device then knx_apply_device write them to the interface's KNXnet/IP \
             parameter object. `device` is what the interface reported the last time it \
             was read (`bussard status {ia}`, `describe`, or a plan)."
        ),
    }))
}

/// Settles the parameter changes of `changes` against the product models of
/// the devices they name (issue #279): a label on one side and its code on
/// the other is no change, and an enum value reads as its label with the
/// code after it. `models` are the new side, then the old.
pub(crate) fn settle_changes(dir: &Path, changes: &mut ChangeSet, models: [&Model; 2]) {
    let devices: std::collections::BTreeSet<IndividualAddress> = changes
        .changes
        .iter()
        .filter(|c| c.kind == ChangeKind::ParameterChanged)
        .filter_map(|c| c.device.as_deref()?.parse().ok())
        .collect();
    if devices.is_empty() {
        return;
    }
    let apps: Vec<&str> = models
        .iter()
        .flat_map(|m| {
            devices.iter().filter_map(|ia| {
                m.devices
                    .get(ia)?
                    .device
                    .product
                    .as_ref()?
                    .application_ref
                    .as_deref()
            })
        })
        .collect();
    let products = ProductModels::load_apps(dir, apps);
    name_parameters(changes, models, &products);
}

/// A diagnostic's identity for the before/after comparison.
fn diagnostic_key(d: &bussard_model::Diagnostic) -> (String, String, String) {
    (d.code.to_string(), d.location.clone(), d.message.clone())
}

/// The validation payload every edit tool returns (issue #279):
/// `{ok, errors, error_count, new_warnings, warning_count}`.
///
/// `errors` are the model's errors after the edit; `new_warnings` the
/// warnings `after` has and `before` did not (same code, location and
/// message), so an edit that adds none returns none. Each list stops at
/// [`MAX_RESULT_DIAGNOSTICS`] with a `note`; `knx_validate` lists all.
fn validation_json(
    before: &[bussard_model::Diagnostic],
    after: &[bussard_model::Diagnostic],
) -> Value {
    let row = |d: &bussard_model::Diagnostic| {
        json!({
            "code": d.code,
            "message": d.message,
            "location": d.location,
        })
    };
    let earlier: std::collections::BTreeSet<(String, String, String)> = before
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(diagnostic_key)
        .collect();
    let errors: Vec<&bussard_model::Diagnostic> = after
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    let warnings: Vec<&bussard_model::Diagnostic> = after
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .collect();
    let new_warnings: Vec<&bussard_model::Diagnostic> = warnings
        .iter()
        .copied()
        .filter(|d| !earlier.contains(&diagnostic_key(d)))
        .collect();
    let mut out = json!({
        "ok": errors.is_empty(),
        "errors": errors.iter().take(MAX_RESULT_DIAGNOSTICS).map(|d| row(d)).collect::<Vec<_>>(),
        "error_count": errors.len(),
        "new_warnings": new_warnings
            .iter()
            .take(MAX_RESULT_DIAGNOSTICS)
            .map(|d| row(d))
            .collect::<Vec<_>>(),
        "warning_count": warnings.len(),
    });
    if (errors.len() > MAX_RESULT_DIAGNOSTICS || new_warnings.len() > MAX_RESULT_DIAGNOSTICS)
        && let Some(map) = out.as_object_mut()
    {
        map.insert(
            "note".into(),
            json!(format!(
                "listing at most {MAX_RESULT_DIAGNOSTICS} errors and {MAX_RESULT_DIAGNOSTICS} new \
                 warnings ({} errors, {} new warnings in all); knx_validate lists every one",
                errors.len(),
                new_warnings.len()
            )),
        );
    }
    out
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

/// Applies `args` to the `[knxnet]` table: the assignment (dhcp drops the
/// static settings), the static settings, the friendly name and the tunnel
/// list. `Err` names the first value that does not parse.
fn set_interface(
    table: &mut bussard_model::knxnet::KnxnetConfig,
    args: &SetInterfaceArgs,
) -> Result<(), String> {
    use bussard_model::knxnet::IpAssignment;
    use std::net::Ipv4Addr;
    let ip = |what: &str, value: &str| -> Result<Option<Ipv4Addr>, String> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        value
            .parse()
            .map(Some)
            .map_err(|_| format!("{what} {value:?} is not an IPv4 address like 192.168.1.80"))
    };
    let ia = |value: &str| -> Result<IndividualAddress, String> {
        value
            .trim()
            .parse()
            .map_err(|_| format!("{value:?} is not an individual address like \"1.1.22\""))
    };
    if let Some(assignment) = &args.assignment {
        table.assignment = match assignment.trim().to_ascii_lowercase().as_str() {
            "dhcp" => IpAssignment::Dhcp,
            "static" | "manual" => IpAssignment::Static,
            other => {
                return Err(format!(
                    "assignment {other:?} is neither \"dhcp\" nor \"static\""
                ));
            }
        };
        if table.assignment == IpAssignment::Dhcp {
            table.address = None;
            table.netmask = None;
            table.gateway = None;
        }
    }
    if let Some(v) = &args.ip_address {
        table.address = ip("ip_address", v)?;
    }
    if let Some(v) = &args.netmask {
        table.netmask = ip("netmask", v)?;
    }
    if let Some(v) = &args.default_gateway {
        table.gateway = ip("default_gateway", v)?;
    }
    if let Some(name) = &args.friendly_name {
        table.friendly_name = (!name.is_empty()).then(|| name.clone());
    }
    if let Some(list) = &args.tunnels {
        table.tunnels = list.iter().map(|t| ia(t)).collect::<Result<_, _>>()?;
    }
    for t in &args.add_tunnels {
        let t = ia(t)?;
        if !table.tunnels.contains(&t) {
            table.tunnels.push(t);
        }
    }
    for t in &args.remove_tunnels {
        let t = ia(t)?;
        table.tunnels.retain(|x| *x != t);
    }
    Ok(())
}
