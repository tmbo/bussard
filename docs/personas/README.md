# Product personas

Internal reference for product decisions. Two people carry the weight of every
bussard feature: the owner who inherits a KNX house and the integrator who
builds one. This directory describes both, walks their journeys step by step,
maps each step to what bussard does today, and names the gaps. The gaps are
written up as ready-to-file issues in [issues.md](issues.md).

The personas are grounded in the KNX Association's project and handover
guidelines, ETS licence terms, integrator checklists, and several hundred forum
threads (knx-user-forum.de, openHAB and Home Assistant communities). Each
persona file ends with its sources.

| File | Persona | One-line summary |
|---|---|---|
| [homeowner.md](homeowner.md) | Nadia, the new owner | Gets the keys to a KNX house, wants to understand it, own it, and change it without paying for every button. |
| [integrator.md](integrator.md) | Jonas, the KNX integrator | Plans, addresses, commissions, documents and hands over KNX installations for customers, then lives with the change requests. |
| [issues.md](issues.md) | both | Twenty issue drafts derived from the journey gaps, with acceptance criteria and labels. |

## How to use the personas

- A feature request should name the persona and the journey stage it serves.
  "Nadia, stage 3 (no project file)" is a complete justification; "would be
  nice" is not.
- When two designs conflict, the owner persona wins on safety and the
  integrator persona wins on throughput. Both are stated in DESIGN.md as the
  primary target (owners and small installations first) and the follow-on
  (larger installations later).
- The journey tables use three columns for bussard: "today" is what ships on
  `main` (marked "pending merge" when it sits on a feature branch), "gap" is
  what the persona still has to do by hand or with ETS, and the issue column
  points at the draft that closes the gap.

## What both personas share

Four facts shape both journeys and are worth keeping in mind for every
design decision.

The ETS project file is the single point of failure. It holds the names, the
room structure, the parameters and, for KNX Secure, the keys. Devices hold the
tables but none of the meaning. KNX's own guidelines oblige the outgoing
integrator to hand over the latest project, yet withholding it is common, and
without it the owner faces a two-to-three day reconstruction job or a rebuild
from scratch. bussard's YAML model in git is the answer to this problem, so
everything that gets the model populated, backed up and legible is on the
critical path.

ETS is Windows-only and priced for professionals. ETS6 Home is 350 EUR, caps at
64 devices and one project, and a normal single-family house often exceeds 64
devices. Professional is 1,000 EUR. Everything bussard can do without ETS is a
direct saving for the owner and a smaller licence dependency for the
integrator's customers.

Neither persona is git-native, and exchange happens by file. Owners will not
learn git or read YAML diffs, and integrators deliver a file on a USB stick,
as they do with the `.knxproj` today. bussard therefore needs its own history
and undo (D18), a single-file bundle for exchange and backup (D19), and
plain-language rendering of pending changes (D20). Git remains the right layer
for the project's developers and for integrators who want a shared repository,
and the model directory stays git-friendly, but nothing in the owner journey
may depend on it.

The bus is shared and slow, and writes are physical. A tunnelling interface
has a fixed number of connections, often one to five, and Home Assistant, ETS
and bussard each need their own. A failed download leaves a device unloaded.
Both personas need plan-before-apply, verification and backups, and the
integrator additionally needs to do it sixty times in an afternoon.

## How the personas work with bussard in 2026: the assistant is the operator

Neither Nadia nor Jonas drives bussard command by command. Each works with an
LLM assistant connected to `bussard mcp`, and the assistant does the reading,
the proposing and the model editing. The split:

| The assistant does, over MCP | The human does, on the CLI |
|---|---|
| Answers "what do I have" from `knx_audit` and `knx_project_summary`. | Installs bussard, runs `init`, connects the assistant. |
| Runs the learn loop: "press the button", `knx_wait_for_telegram`, `knx_infer_group`, then `knx_set_group` and `knx_add_link` once the human confirms. | Presses the buttons. |
| Edits the model with `knx_set_group`, `knx_add_link`, `knx_remove_link`, `knx_set_device`, `knx_set_parameter`, and quotes the sentence each edit returns. | Reads the sentence and says yes or no. |
| Explains the past with `knx_history` and `knx_describe_change`, and reverts with `knx_undo`. | Programs devices: `plan`, `apply`, `flash`, behind a confirmation and the real-gateway gate. |
| Drafts `tests.yaml` and, on a write-enabled server, runs it with `knx_run_tests`. | Runs the physical ceremonies: `commission`, `replace`, `adopt`. |
| Explains what a received `.knxproj` or bundle would change with `knx_diff_project`, and exports with `knx_export_bundle`. | Imports the file with `bussard import` and exports a bundle to a USB stick. |

Three properties make this safe. Every model edit is snapshotted before it is
written and rendered in plain sentences, so the human judges a sentence, not a
YAML diff, and any edit is one undo away. Protected group addresses are
refused over MCP with no override. Programming a device is not an MCP tool at
all, so nothing an assistant does changes a device's tables or parameters until
a human runs `apply` or `flash`. Group writes over MCP exist only on a server
started with `--allow-writes`.

Git is optional throughout. History and undo are built in, and exchange with a
professional is by file ([collaboration.md](../collaboration.md)). The owner's
path is written up in [the first weekend guide](../getting-started-owner.md).
