//! What this server tells the assistant it can do (issue #272).
//!
//! Clients load tools lazily, so a tool description or a result string is
//! often the only guidance an assistant has at the moment of a call. Every
//! such string that depends on what the server may do comes from here, built
//! from the server's active tiers ([`Tiers`]): the server instructions, the
//! `next_step` after a model edit, the `server` and `capabilities` fields of
//! `knx_project_summary`, and `how_to_change` on `knx_show_device`.
//!
//! The tiers are cumulative: `passive` observes only; `read` (the default)
//! also reads group values and introspects devices; `write`
//! (`--allow-writes`) sends group values; `programming`
//! (`--allow-programming`) writes a device's group-address and association
//! tables through `knx_plan_device` and `knx_apply_device`. Parameter values
//! are edited in the device files with `knx_set_parameter` at every tier, but
//! no MCP tool writes them to a device yet: that half of a push is the CLI's
//! `bussard apply`, and every string here says so next to the MCP tool that
//! pushes the links.

use std::collections::BTreeSet;

use bussard_model::change::{ChangeKind, ChangeSet};
use serde_json::{Value, json};

use crate::state::SharedState;

/// The CLI commands no MCP tool replaces, named once in the instructions.
const CLI_ONLY: &str = "Still needs the CLI: `bussard flash` to load a new application \
    program, `bussard adopt`, `bussard replace` and `bussard commission`.";

/// What still needs ETS, named once in the instructions.
const ETS_ONLY: &str = "Still needs ETS: the Secure activation of a fresh device, and any \
    setting the device's product model does not expose.";

/// The server's active tiers, as the tool router registered them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tiers {
    /// `--passive`: nothing is transmitted on the bus.
    pub passive: bool,
    /// `--allow-writes`: `knx_write_group` and `knx_run_tests` are registered.
    pub writes: bool,
    /// `--allow-programming`: `knx_plan_device` and `knx_apply_device` are
    /// registered.
    pub programming: bool,
    /// The model-edit tools are registered (no `--no-model-edits`).
    pub model_edits: bool,
}

impl Tiers {
    /// The tiers of `state`, with the same rules [`crate::server::BussardMcp::new`]
    /// uses to trim the router: passive mode wins over writes and programming.
    pub fn of(state: &SharedState) -> Tiers {
        Tiers {
            passive: state.passive,
            writes: state.allow_writes && !state.passive,
            programming: state.programming.is_some() && !state.passive,
            model_edits: !state.no_model_edits,
        }
    }

    /// The tier names in order: `passive`, or `read` followed by `write`
    /// and `programming` when those are on.
    pub fn names(&self) -> Vec<&'static str> {
        if self.passive {
            return vec!["passive"];
        }
        let mut names = vec!["read"];
        if self.writes {
            names.push("write");
        }
        if self.programming {
            names.push("programming");
        }
        names
    }

    /// The `server` object of `knx_project_summary`.
    pub fn summary_json(&self) -> Value {
        json!({
            "tiers": self.names(),
            "passive": self.passive,
            "writes": self.writes,
            "programming": self.programming,
            "model_edits": self.model_edits,
        })
    }

    /// One paragraph saying what an assistant may do through this server, for
    /// `knx_project_summary`'s `capabilities` field.
    pub fn capabilities(&self) -> String {
        let mut parts = Vec::new();
        parts.push(if self.passive {
            "This server observes the bus without transmitting and reads the model files."
                .to_string()
        } else {
            "This server reads the model files, observes the bus, reads group values \
             (knx_read_group) and introspects devices (knx_describe_device)."
                .to_string()
        });
        parts.push(if self.model_edits {
            "It edits the model files: group addresses (knx_set_group), links \
             (knx_add_link, knx_remove_link), names and rooms (knx_set_device) and parameter \
             values (knx_set_parameter, with the keys knx_show_device lists)."
                .to_string()
        } else {
            "Model edits are off (--no-model-edits).".to_string()
        });
        if !self.passive {
            parts.push(if self.writes {
                "It writes group values to the bus (knx_write_group) and runs the acceptance \
                 suite (knx_run_tests)."
                    .to_string()
            } else {
                "Group writes are off (no --allow-writes).".to_string()
            });
        }
        parts.push(self.push_paragraph());
        parts.join(" ")
    }

    /// How an edit reaches a device at this tier, as used in the instructions
    /// and the capabilities sentence.
    fn push_paragraph(&self) -> String {
        if self.programming {
            "It pushes a device's links: knx_plan_device reads the device and returns the \
             plan, and knx_apply_device writes the group-address and association tables after \
             the human said yes to that plan, over KNX Data Secure when the server's keyring \
             lists the device. Parameter values are not written over MCP yet: knx_apply_device \
             writes links only, and the parameter write is `bussard apply <ia>` at the CLI."
                .to_string()
        } else {
            "Nothing it edits reaches a device from here: this server runs without \
             --allow-programming. Restarted with that flag, knx_plan_device and \
             knx_apply_device push a device's links; without it, the push is `bussard plan \
             <ia>` and `bussard apply <ia>` at the CLI, which also write parameter values."
                .to_string()
        }
    }

    /// The server instructions (`initialize` result) for this tier.
    pub fn instructions(&self) -> String {
        let mut out = vec![format!(
            "bussard: KNX as code over MCP. The installation lives as TOML files \
             (groups.toml, devices/*.toml, bussard.lock); this server reads and edits them and \
             works with the live bus. Active tiers: {}. Start with knx_project_summary (its \
             `server` and `capabilities` fields say what this server may do), then \
             knx_model_lookup, knx_get_group, knx_get_device and knx_show_device to explore, \
             and knx_validate and knx_audit to check the model.",
            self.names().join(", ")
        )];
        out.push(if self.passive {
            "Observe with knx_recent_telegrams and knx_wait_for_telegram (the latter enables \
             'press the button now' debugging). Passive mode: nothing is transmitted, so \
             knx_read_group and knx_describe_device are not available."
                .to_string()
        } else {
            "Observe with knx_recent_telegrams and knx_wait_for_telegram (the latter enables \
             'press the button now' debugging); knx_read_group reads a value and \
             knx_describe_device introspects a device's interface objects over the bus."
                .to_string()
        });
        out.push(if self.model_edits {
            "Change the model with the edit tools, never by writing files: knx_set_group, \
             knx_add_link, knx_remove_link, knx_set_device, knx_set_parameter and knx_undo. \
             Parameters are edited with knx_set_parameter using the keys knx_show_device lists \
             (the device needs its product model). Every edit snapshots the files first and \
             returns the change as sentences: quote them to the human, and follow the result's \
             next_step."
                .to_string()
        } else {
            "Model edits are off (--no-model-edits): the model is read-only here.".to_string()
        });
        if !self.passive {
            out.push(if self.writes {
                "knx_write_group writes a group value to the physical bus (actuators move) and \
                 knx_run_tests runs the acceptance suite; both refuse protected group addresses. \
                 Ask the human when a write's intent or safety is unclear."
                    .to_string()
            } else {
                "Group writes are off: restart with --allow-writes for knx_write_group.".to_string()
            });
        }
        if self.programming {
            out.push(
                "Push a device with knx_plan_device, show the plan to the human in full, and \
                 call knx_apply_device only after an explicit yes in this conversation. It \
                 writes the device's links (group-address and association tables), over KNX \
                 Data Secure when the server's keyring lists the device. Parameter values are \
                 not written over MCP yet: knx_apply_device writes links only, and after \
                 knx_set_parameter the parameter write is `bussard apply <ia>` at the CLI."
                    .to_string(),
            );
        } else {
            out.push(
                "This server runs without --allow-programming, so edits stay in the files. \
                 Restarted with that flag, knx_plan_device and knx_apply_device push a \
                 device's links; without it, the push is `bussard plan <ia>` and `bussard \
                 apply <ia>` at the CLI."
                    .to_string(),
            );
        }
        out.push(CLI_ONLY.to_string());
        out.push(ETS_ONLY.to_string());
        out.join(" ")
    }

    /// The `next_step` after a model edit that produced `changes`: which
    /// devices the edit touches (from the link and parameter changes) and how
    /// the edit reaches them at this tier.
    pub fn next_step(&self, changes: &ChangeSet) -> String {
        let push = Push::of(changes);
        if push.links.is_empty() && push.parameters.is_empty() {
            return "Nothing to push: this change is only in the model files (names, rooms and \
                    group-address metadata are stored in no device). Links that use a group \
                    address are pushed per device with knx_plan_device and knx_apply_device."
                .to_string();
        }
        let mut out = vec!["Nothing has reached any device yet.".to_string()];
        if !push.links.is_empty() {
            let devices = list(&push.links);
            out.push(if self.programming {
                format!(
                    "Push the links with knx_plan_device for {devices} (show the plan to the \
                     human) and knx_apply_device after an explicit yes."
                )
            } else {
                format!(
                    "This server runs without --allow-programming: restart it with that flag \
                     to push the links with knx_plan_device and knx_apply_device for \
                     {devices}, or push from the CLI with {}.",
                    cli(&push.links)
                )
            });
        }
        if !push.parameters.is_empty() {
            let devices = list(&push.parameters);
            out.push(if self.programming {
                format!(
                    "Parameter values are not written over MCP yet: knx_plan_device and \
                     knx_apply_device push links only, so the parameter change on {devices} \
                     reaches the device with {} at the CLI. Tell the human so.",
                    cli(&push.parameters)
                )
            } else {
                format!(
                    "Parameter values are not written over MCP yet (knx_apply_device, with \
                     --allow-programming, pushes links only): the parameter change on \
                     {devices} reaches the device with {} at the CLI.",
                    cli(&push.parameters)
                )
            });
        }
        out.join(" ")
    }
}

/// The devices a change set needs pushed, split by what reaches them.
struct Push {
    /// Devices whose links (or whole device file) changed.
    links: BTreeSet<String>,
    /// Devices whose parameter values changed.
    parameters: BTreeSet<String>,
}

impl Push {
    /// Collects the devices from `changes`. Group-address metadata, device
    /// names, rooms and channel names are stored in no device, and a removed
    /// device or a connection change has nothing to push to.
    fn of(changes: &ChangeSet) -> Push {
        let mut push = Push {
            links: BTreeSet::new(),
            parameters: BTreeSet::new(),
        };
        for change in &changes.changes {
            let Some(device) = change.device.clone() else {
                continue;
            };
            match change.kind {
                ChangeKind::LinkAdded
                | ChangeKind::LinkRemoved
                | ChangeKind::DeviceAdded
                | ChangeKind::DeviceProductChanged => {
                    push.links.insert(device);
                }
                ChangeKind::ParameterChanged => {
                    push.parameters.insert(device);
                }
                _ => {}
            }
        }
        push
    }
}

/// `1.1.4`, `1.1.4 and 1.1.5`, `1.1.4, 1.1.5 and 1.1.6`.
fn list(devices: &BTreeSet<String>) -> String {
    let items: Vec<&str> = devices.iter().map(String::as_str).collect();
    match items.split_last() {
        None => String::new(),
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// The CLI push for `devices`: `` `bussard plan 1.1.4` and `bussard apply 1.1.4` ``.
fn cli(devices: &BTreeSet<String>) -> String {
    devices
        .iter()
        .map(|ia| format!("`bussard plan {ia}` and `bussard apply {ia}`"))
        .collect::<Vec<_>>()
        .join(", then ")
}

/// `knx_show_device`'s `how_to_change`: how the listed parameters and objects
/// are changed and pushed. Without a product model, the parameters cannot be
/// edited over MCP yet, and the view's first note says what to run.
pub fn how_to_change(product_model: bool, notes: &[String]) -> String {
    let push = "push: knx_plan_device then knx_apply_device (with --allow-programming) write \
                the links; parameter values are written by `bussard apply <ia>` at the CLI, \
                the MCP tier does not write them yet";
    if product_model {
        format!(
            "parameters: knx_set_parameter with the key shown (add `channel` when the key \
             repeats across channels) and a value from its choices or range; links: \
             knx_add_link/knx_remove_link with the object number; {push}"
        )
    } else {
        let why = notes
            .first()
            .map(String::as_str)
            .unwrap_or("no product data for this device");
        format!(
            "parameters: not editable yet, knx_set_parameter needs the product model to check \
             values against ({why}); links: knx_add_link/knx_remove_link with the object \
             number; {push}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::change::Change;

    fn tiers(passive: bool, writes: bool, programming: bool) -> Tiers {
        Tiers {
            passive,
            writes,
            programming,
            model_edits: true,
        }
    }

    fn change(kind: ChangeKind, device: &str) -> Change {
        Change {
            kind,
            sentence: String::new(),
            touches_protected: false,
            device: Some(device.to_string()),
            group: None,
            object: None,
            role: None,
            field: None,
            from: None,
            to: None,
        }
    }

    #[test]
    fn test_names_are_cumulative() {
        assert_eq!(tiers(true, false, false).names(), ["passive"]);
        assert_eq!(tiers(false, false, false).names(), ["read"]);
        assert_eq!(
            tiers(false, true, true).names(),
            ["read", "write", "programming"]
        );
    }

    #[test]
    fn test_next_step_names_the_device_and_the_mcp_tools() {
        let set = ChangeSet {
            changes: vec![change(ChangeKind::LinkAdded, "1.1.4")],
        };
        let on = tiers(false, false, true).next_step(&set);
        assert!(on.contains("knx_plan_device for 1.1.4"), "{on}");
        assert!(!on.contains("bussard plan"), "{on}");
        let off = tiers(false, false, false).next_step(&set);
        assert!(off.contains("--allow-programming"), "{off}");
        assert!(off.contains("`bussard plan 1.1.4`"), "{off}");
    }

    #[test]
    fn test_next_step_metadata_has_nothing_to_push() {
        let set = ChangeSet {
            changes: vec![change(ChangeKind::DeviceRenamed, "1.1.4")],
        };
        assert!(
            tiers(false, false, true)
                .next_step(&set)
                .starts_with("Nothing to push")
        );
    }
}
