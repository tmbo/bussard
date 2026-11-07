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
//! (`--allow-programming`) pushes a device through `knx_plan_device` and
//! `knx_apply_device`: its group-address and association tables and the
//! parameter values that differ from the model (issue #274). Parameter values
//! are edited in the device files with `knx_set_parameter` at every tier; the
//! push is the same pair of tools, or `bussard plan` and `bussard apply` at the
//! CLI on a server without that tier.
//!
//! The Home Assistant tier (issue #280, `[home_assistant]` in `bussard.toml`
//! plus `--allow-home-assistant`) stands beside these: it never touches the
//! bus, so it can be on in any of them, passive included.

use std::collections::BTreeSet;

use bussard_model::change::{ChangeKind, ChangeSet};
use bussard_model::{IndividualAddress, Model};
use serde_json::{Value, json};

use crate::state::SharedState;

/// What still needs ETS, named once in the instructions.
const ETS_ONLY: &str = include_str!("../guidance/instructions/ets_only.md");

/// How to talk to the human (issue #306), named once in the instructions.
pub const HOW_TO_TALK: &str = include_str!("../guidance/instructions/how_to_talk.md");

/// The Home Assistant tier in the capabilities paragraph.
const HA_CAPABILITY: &str = include_str!("../guidance/capabilities/home_assistant.md");

/// The Home Assistant tier in the instructions.
const HA_INSTRUCTIONS: &str = include_str!("../guidance/instructions/home_assistant.md");

/// What a `--passive` server does.
const CAP_PASSIVE: &str = include_str!("../guidance/capabilities/passive.md");

/// What a server that may transmit reads and observes.
const CAP_BUS: &str = include_str!("../guidance/capabilities/bus.md");

/// The model edits.
const CAP_EDITS: &str = include_str!("../guidance/capabilities/edits.md");

/// The model edits are off (`--no-model-edits`).
const CAP_EDITS_OFF: &str = include_str!("../guidance/capabilities/edits_off.md");

/// The group writes (`--allow-writes`).
const CAP_WRITES: &str = include_str!("../guidance/capabilities/writes.md");

/// The group writes are off.
const CAP_WRITES_OFF: &str = include_str!("../guidance/capabilities/writes_off.md");

/// The closing sentence on summaries.
const CAP_SUMMARY: &str = include_str!("../guidance/capabilities/summary.md");

/// How an edit reaches a device with `--allow-programming`.
const PUSH_PROGRAMMING: &str = include_str!("../guidance/capabilities/push_programming.md");

/// How an edit reaches a device without `--allow-programming`.
const PUSH_CLI: &str = include_str!("../guidance/capabilities/push_cli.md");

/// The opening paragraph; `{tiers}` is replaced by the active tiers.
const INTRO: &str = include_str!("../guidance/instructions/intro.md");

/// Observing in `--passive` mode.
const OBSERVE_PASSIVE: &str = include_str!("../guidance/instructions/observe_passive.md");

/// Observing and reading when the server may transmit.
const OBSERVE_BUS: &str = include_str!("../guidance/instructions/observe_bus.md");

/// The model edits and the certificate enrolment.
const EDITS: &str = include_str!("../guidance/instructions/edits.md");

/// The model edits are off (`--no-model-edits`).
const EDITS_OFF: &str = include_str!("../guidance/instructions/edits_off.md");

/// The group writes (`--allow-writes`).
const WRITES: &str = include_str!("../guidance/instructions/writes.md");

/// The group writes are off.
const WRITES_OFF: &str = include_str!("../guidance/instructions/writes_off.md");

/// The programming tier (`--allow-programming`).
const PROGRAMMING: &str = include_str!("../guidance/instructions/programming.md");

/// The programming tier is off: the CLI commands.
const PROGRAMMING_OFF: &str = include_str!("../guidance/instructions/programming_off.md");

/// The `next_step` after a model edit on this server: [`Tiers::next_step`],
/// plus the Home Assistant line when that tier is on and the edit touched a
/// group address Home Assistant's KNX config uses.
pub fn next_step(state: &SharedState, changes: &ChangeSet) -> String {
    let model = state.model.current();
    let mut out = Tiers::of(state).next_step(changes, Some(&model));
    if let Some(line) = crate::tools_ha::next_step_line(state, changes) {
        out.push(' ');
        out.push_str(&line);
    }
    out
}

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
    /// The Home Assistant tier: `knx_ha_status`, `knx_ha_plan` and
    /// `knx_ha_apply` are registered.
    pub home_assistant: bool,
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
            home_assistant: state.home_assistant.is_some(),
        }
    }

    /// Whether these tiers register the tools of `tier`.
    pub fn allows(&self, tier: crate::Tier) -> bool {
        match tier {
            crate::Tier::Read => true,
            crate::Tier::Bus => !self.passive,
            crate::Tier::Writes => self.writes,
            crate::Tier::ModelEdit => self.model_edits,
            crate::Tier::Programming => self.programming,
            crate::Tier::HomeAssistant => self.home_assistant,
        }
    }

    /// The tier names in order: `passive`, or `read` followed by `write`
    /// and `programming` when those are on; then `home_assistant` when on.
    pub fn names(&self) -> Vec<&'static str> {
        let mut names = if self.passive {
            vec!["passive"]
        } else {
            let mut names = vec!["read"];
            if self.writes {
                names.push("write");
            }
            if self.programming {
                names.push("programming");
            }
            names
        };
        if self.home_assistant {
            names.push("home_assistant");
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
            "home_assistant": self.home_assistant,
        })
    }

    /// One paragraph saying what an assistant may do through this server, for
    /// `knx_project_summary`'s `capabilities` field.
    pub fn capabilities(&self) -> String {
        let mut parts = Vec::new();
        parts.push(if self.passive {
            CAP_PASSIVE.to_string()
        } else {
            CAP_BUS.to_string()
        });
        parts.push(if self.model_edits {
            CAP_EDITS.to_string()
        } else {
            CAP_EDITS_OFF.to_string()
        });
        if !self.passive {
            parts.push(if self.writes {
                CAP_WRITES.to_string()
            } else {
                CAP_WRITES_OFF.to_string()
            });
        }
        parts.push(self.push_paragraph());
        if self.home_assistant {
            parts.push(HA_CAPABILITY.to_string());
        }
        parts.push(CAP_SUMMARY.to_string());
        parts.join(" ")
    }

    /// How an edit reaches a device at this tier, as used in the instructions
    /// and the capabilities sentence.
    fn push_paragraph(&self) -> String {
        if self.programming {
            PUSH_PROGRAMMING.to_string()
        } else {
            PUSH_CLI.to_string()
        }
    }

    /// How a parameter that shows or hides com-objects, and the load of the
    /// application bussard.lock pins (issue #750), reach device `ia` (`<ia>`
    /// when `None`) at this tier (issue #303): the same plan and apply pair
    /// as a full download with `--allow-programming`, else `bussard flash`
    /// at the CLI.
    pub fn flash_push(&self, ia: Option<IndividualAddress>) -> String {
        let ia = ia.map_or_else(|| "<ia>".to_string(), |ia| ia.to_string());
        if self.programming {
            let (min, max) = bussard_service::flash::DEVICE_OFFLINE_SECONDS;
            format!(
                "A parameter that shows or hides com-objects is pushed by the same \
                 knx_plan_device / knx_apply_device pair; the plan says `method: flash`, the \
                 device restarts and is offline for the stated time ({min} to {max} s), and the \
                 human's yes must be a yes to flashing {ia}. So is a device that does not run \
                 the application program bussard.lock pins (another one, or none loaded): the \
                 plan's sentences say the application must be loaded, and one yes to its \
                 question loads it and writes the project's values with it as one job."
            )
        } else {
            format!(
                "A parameter that shows or hides com-objects, and loading the application \
                 program bussard.lock pins into a device, need `bussard flash {ia}` at the CLI; \
                 with --allow-programming, knx_plan_device and knx_apply_device push it as a \
                 flash."
            )
        }
    }

    /// The `needs` sentence of an inactive page or channel of device `ia`
    /// (`<ia>` when `None`) with how this tier runs that push appended: the
    /// model says what kind of push it is
    /// ([`bussard_model::device_view::NEEDS_FLASH`] or
    /// [`bussard_model::device_view::NEEDS_PUSH`]), this says how.
    pub fn needs_how(&self, needs: &str, ia: Option<IndividualAddress>) -> String {
        if needs == bussard_model::device_view::NEEDS_ETS {
            return needs.to_string();
        }
        let at = ia.map_or_else(|| "<ia>".to_string(), |ia| ia.to_string());
        let flash = needs == bussard_model::device_view::NEEDS_FLASH;
        let how = match (flash, self.programming) {
            (true, true) => {
                "set `enable` with knx_set_parameter; knx_plan_device plans the push as \
                             `method: flash` and knx_apply_device runs it"
                    .to_string()
            }
            (true, false) => format!(
                "set `enable` with knx_set_parameter, then `bussard flash {at}` at the CLI (with \
                 --allow-programming, knx_plan_device and knx_apply_device push it as a flash)"
            ),
            (false, true) => {
                "set `enable` with knx_set_parameter, then push it with knx_plan_device and \
                 knx_apply_device"
                    .to_string()
            }
            (false, false) => format!(
                "set `enable` with knx_set_parameter, then `bussard plan {at}` and `bussard apply \
                 {at}` at the CLI (with --allow-programming, knx_plan_device and \
                 knx_apply_device)"
            ),
        };
        format!("{needs}: {how}")
    }

    /// The server instructions (`initialize` result) for this tier.
    pub fn instructions(&self) -> String {
        let mut out = vec![INTRO.replace("{tiers}", &self.names().join(", "))];
        out.push(HOW_TO_TALK.to_string());
        out.push(if self.passive {
            OBSERVE_PASSIVE.to_string()
        } else {
            OBSERVE_BUS.to_string()
        });
        out.push(if self.model_edits {
            EDITS.to_string()
        } else {
            EDITS_OFF.to_string()
        });
        if !self.passive {
            out.push(if self.writes {
                WRITES.to_string()
            } else {
                WRITES_OFF.to_string()
            });
        }
        if self.programming {
            out.push(PROGRAMMING.to_string());
        } else {
            out.push(PROGRAMMING_OFF.to_string());
        }
        if self.home_assistant {
            out.push(HA_INSTRUCTIONS.to_string());
        }
        out.push(self.flash_push(None));
        out.push(ETS_ONLY.to_string());
        out.join(" ")
    }

    /// The `next_step` after a model edit that produced `changes`: which
    /// devices the edit touches (from the link and parameter changes), named
    /// by name and room from `model` (issue #306), and how the edit reaches
    /// them at this tier. The individual address appears only inside the
    /// tool call or CLI command that needs it.
    pub fn next_step(&self, changes: &ChangeSet, model: Option<&Model>) -> String {
        let push = Push::of(changes);
        if push.links.is_empty() && push.parameters.is_empty() {
            return "Nothing to push: this change is only in the project files (names, rooms and \
                    group-address metadata are stored in no device). Links that use a group \
                    address are pushed per device with knx_plan_device and knx_apply_device."
                .to_string();
        }
        let mut out = vec!["Nothing has reached any device yet.".to_string()];
        let devices: BTreeSet<String> = push.links.union(&push.parameters).cloned().collect();
        let what = match (push.links.is_empty(), push.parameters.is_empty()) {
            (false, false) => "the links and parameter values",
            (false, true) => "the links",
            _ => "the parameter values",
        };
        let names = list(&devices, model);
        out.push(if self.programming {
            format!(
                "Push {what} of {names} with {} (say the plan's summary and \
                 what_you_will_notice to the human, then show its sentences: every changed link \
                 and parameter) and knx_apply_device after an explicit yes.",
                calls(&devices)
            )
        } else {
            format!(
                "This server runs without --allow-programming: restart it with that flag to \
                 push {what} of {names} with knx_plan_device and knx_apply_device, or push from \
                 the CLI with {}.",
                cli(&devices)
            )
        });
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
                | ChangeKind::DeviceProductChanged
                | ChangeKind::ObjectSecurityChanged
                | ChangeKind::InterfaceChanged => {
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

/// The devices by name and room (`Hallway push button in Hallway and
/// Dimmer`), each by its address when `model` has no name for it.
fn list(devices: &BTreeSet<String>, model: Option<&Model>) -> String {
    let items: Vec<String> = devices
        .iter()
        .map(|ia| match (model, ia.parse::<IndividualAddress>()) {
            (Some(model), Ok(ia)) => crate::everyday::device_phrase(model, ia),
            _ => format!("device {ia}"),
        })
        .collect();
    bussard_model::text::join_and(&items)
}

/// The MCP push call per device: `` knx_plan_device `{"address": "1.1.4"}` ``.
fn calls(devices: &BTreeSet<String>) -> String {
    devices
        .iter()
        .map(|ia| format!("knx_plan_device `{{\"address\": \"{ia}\"}}`"))
        .collect::<Vec<_>>()
        .join(", then ")
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
                the links and the parameter values that differ";
    if product_model {
        format!(
            "parameters: knx_set_parameter with the key shown and a value from its choices or \
             range; links: knx_add_link/knx_remove_link with the object number; {push}. {}.",
            crate::param_keys::KEY_GRAMMAR
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
            home_assistant: false,
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
    fn test_needs_how_says_how_at_each_tier() -> Result<(), Box<dyn std::error::Error>> {
        use bussard_model::device_view::{NEEDS_FLASH, NEEDS_PUSH};
        let ia: IndividualAddress = "1.1.202".parse()?;
        let programming = tiers(false, false, true).needs_how(NEEDS_FLASH, Some(ia));
        assert!(programming.starts_with(NEEDS_FLASH), "{programming}");
        assert!(programming.contains("`method: flash`"), "{programming}");
        assert!(!programming.contains("bussard flash"), "{programming}");
        let read = tiers(false, false, false).needs_how(NEEDS_FLASH, Some(ia));
        assert!(read.contains("`bussard flash 1.1.202`"), "{read}");
        let push = tiers(false, false, true).needs_how(NEEDS_PUSH, Some(ia));
        assert!(
            push.contains("knx_plan_device and knx_apply_device") && !push.contains("flash"),
            "{push}"
        );
        let push = tiers(false, false, false).needs_how(NEEDS_PUSH, None);
        assert!(push.contains("`bussard apply <ia>`"), "{push}");
        Ok(())
    }

    #[test]
    fn test_instructions_say_how_to_talk() {
        for t in [tiers(true, false, false), tiers(false, true, true)] {
            let text = t.instructions();
            assert!(text.contains("homeowner"), "{text}");
            assert!(text.contains("rooms, device names"), "{text}");
            assert!(text.contains("ids only in tool calls"), "{text}");
            assert!(text.contains("`summary`"), "{text}");
            assert!(!text.contains("quote them to the human"), "{text}");
        }
    }

    #[test]
    fn test_next_step_names_devices_by_name_and_room() -> Result<(), Box<dyn std::error::Error>> {
        use bussard_model::loader::LoadedDevice;
        use bussard_model::schema::{Device, Location};
        let ia: IndividualAddress = "1.1.4".parse()?;
        let mut model = Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices: Default::default(),
        };
        model.devices.insert(
            ia,
            LoadedDevice {
                device: Device {
                    address: ia,
                    name: "Hallway push button".to_string(),
                    description: None,
                    location: Some(Location {
                        floor: None,
                        room: Some("Hallway".to_string()),
                    }),
                    replaced: None,
                    product: None,
                    channels: Default::default(),
                    parameters: Default::default(),
                    module_bases: Default::default(),
                    com_objects: Default::default(),
                    security: None,
                    application_override: None,
                    knxnet: None,
                    lock: Default::default(),
                },
                file_stem: "1.1.4".to_string(),
            },
        );
        let set = ChangeSet {
            changes: vec![change(ChangeKind::LinkAdded, "1.1.4")],
        };
        for t in [tiers(false, false, true), tiers(false, false, false)] {
            let step = t.next_step(&set, Some(&model));
            assert!(step.contains("Hallway push button in Hallway"), "{step}");
            // The address is only inside the call or the command.
            let outside = step
                .replace("`{\"address\": \"1.1.4\"}`", "")
                .replace("`bussard plan 1.1.4`", "")
                .replace("`bussard apply 1.1.4`", "");
            assert!(!outside.contains("1.1.4"), "{step}");
        }
        Ok(())
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
        let on = tiers(false, false, true).next_step(&set, None);
        assert!(
            on.contains("of device 1.1.4 with knx_plan_device `{\"address\": \"1.1.4\"}`"),
            "{on}"
        );
        assert!(!on.contains("bussard plan"), "{on}");
        let off = tiers(false, false, false).next_step(&set, None);
        assert!(off.contains("--allow-programming"), "{off}");
        assert!(off.contains("`bussard plan 1.1.4`"), "{off}");
    }

    #[test]
    fn test_next_step_pushes_parameters_with_the_mcp_tools() {
        let set = ChangeSet {
            changes: vec![change(ChangeKind::ParameterChanged, "1.1.18")],
        };
        let on = tiers(false, false, true).next_step(&set, None);
        assert!(
            on.contains("Push the parameter values of device 1.1.18 with knx_plan_device"),
            "{on}"
        );
        assert!(!on.contains("bussard apply"), "{on}");
        let off = tiers(false, false, false).next_step(&set, None);
        assert!(off.contains("`bussard apply 1.1.18`"), "{off}");
        assert!(off.contains("knx_apply_device"), "{off}");
    }

    #[test]
    fn test_home_assistant_tier_is_named_and_explained() {
        let mut ha = tiers(true, false, false);
        ha.home_assistant = true;
        assert_eq!(ha.names(), ["passive", "home_assistant"]);
        assert_eq!(ha.summary_json()["home_assistant"], true);
        assert!(ha.instructions().contains("knx_ha_plan"));
        assert!(ha.capabilities().contains("knx_ha_apply"));
        let off = tiers(false, false, false);
        assert!(!off.instructions().contains("knx_ha_"));
        assert_eq!(off.summary_json()["home_assistant"], false);
    }

    #[test]
    fn test_next_step_metadata_has_nothing_to_push() {
        let set = ChangeSet {
            changes: vec![change(ChangeKind::DeviceRenamed, "1.1.4")],
        };
        assert!(
            tiers(false, false, true)
                .next_step(&set, None)
                .starts_with("Nothing to push")
        );
    }
}
