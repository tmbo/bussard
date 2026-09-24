# Persona: Nadia, the new owner

Nadia has just taken the keys to a house with a KNX installation she did not
plan. The installation works, mostly. She wants to know what she owns, make it
behave the way her family lives, connect it to the smart-home platform she
already uses, and never be locked out of her own walls. She can install
software and follow a terminal tutorial, and she talks to an LLM assistant
daily. She has never used git, does not want to learn it, and will not read a
file diff to decide whether a change is safe. She is not an electrician and has
no ETS licence.

## Profile

| | |
|---|---|
| Situation | Bought a 2016 build with KNX lighting, blinds, heating and a weather station. About 70 devices on two lines. The integrator who built it has since closed. |
| Skills | Installs software and follows terminal tutorials. Runs Home Assistant. Has never opened ETS or used git. |
| Budget | Willing to spend a few hundred euros on hardware (IP interface, a spare actuator). Not willing to spend 1,000 EUR on ETS Professional plus 500 EUR on a reconstruction app, and ETS Home's 64-device cap does not fit her house. |
| Fears | Being locked out (BCU key, lost passwords), breaking heating or blinds in winter, paying a stranger 800 EUR to relabel a button. |
| Success | She can say what every group address does, change a button without an integrator, undo a change she regrets, and has a backup that survives the death of any single device or laptop. |

Three handover scenarios cover most real owners. The journey below applies to
all three, and the table under each stage notes where they diverge.

- Scenario A, full handover: `.knxproj`, project password, `.knxkeys` if
  Secure devices exist, gateway credentials, device and GA lists, as-built plans.
  This is what the KNX handover checklist prescribes. Rare in practice.
- Scenario B, partial handover: an older `.knxproj` that predates the last
  changes, or a project without password or keyring, or a project the previous
  owner never received but the integrator will still sell.
- Scenario C, nothing: no file, no documentation, sometimes no IP interface.
  Common in resales and after integrator insolvency. Integrators quote one day
  for reconstruction with schematics and two to three days without, and the
  result still lacks every name and room.

## Journey map

### Stage 0. Before the keys: the contract

What she does: negotiates what gets handed over. The KNX Project Design
Guidelines say the outgoing integrator "is obliged to hand over the very latest
version of the project data"; the Swiss 2024 guidelines say it "must" be handed
over; German forum consensus is that the file belongs to whoever paid for it.
Court rulings point both ways, so everything hinges on the contract. The usual
compromise with a warranty-conscious integrator is a password-protected copy
with the password in a sealed envelope.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| A checklist of what to demand | [handover-checklist.md](../handover-checklist.md), one printed page following the KNX handover and security checklists, with a section for the bussard bundle and its checksum. | None. | D2 |

### Stage 1. Day one: what is in the cabinet?

What she does: opens the distribution board, photographs labels, finds the
power supplies, looks for a KNXnet/IP interface. Many 2010s houses have only a
USB or serial interface, so the first purchase is often an IP interface. If one
exists she needs its IP address and, on newer gateways, its tunnelling
password.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Find the gateway | `bussard init` discovers gateways by multicast, writes `bussard.toml`, and prints the tunnel budget (`4 tunnels, 1 in use`); a full interface is reported as such and exits 4 instead of timing out (pending merge). | A Secure-only interface is still refused. | D13, existing #71 |
| Know what devices exist | `bussard scan 1.1` lists every responding device with mask, manufacturer and order number. `bussard audit --live` probes every modelled device and reports which answered (pending merge). | A scan of an unknown house takes minutes per line; `reconstruct --line` is the only way to keep what it found. | D1 |
| Know what bussard can manage | `bussard audit` and the `knx_audit` MCP tool group devices by mask with what bussard can do for each, from the same table the refusals use (pending merge). The assistant answers "which of my devices can you program?" directly. | None. | D1 |

### Stage 2. Import what she was given (scenarios A and B)

What she does: runs the import, types the project password, looks at the
result.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Turn the project into something legible | `bussard import house.knxproj`, then the assistant calls `knx_audit` and summarises: devices per mask, GAs without a DPT or name, devices without a room, one-sided links, Secure devices (pending merge). `bussard viz` shows the house by floor and room. | The audit does not report BCU key status per device. | D1 |
| Handle the keyring | `bussard keyring house.knxkeys` inspects the export; `--keyring` unlocks tool access on `describe`, `apply`, `flash`; `audit --keyring` reports which Secure devices have a tool key in it (pending merge). | KNXnet/IP Secure interfaces are unsupported. | existing #71 |
| Compare the file to the house (scenario B) | `bussard plan --line 1.1` diffs every model device on the line against its live tables in one run, with a summary table. `audit --live` adds the scan delta. | None. | D8 |

### Stage 3. Reconstruct from the bus (scenario C)

What she does: with no project file she has two tools. ETS with the paid
Reconstruction app recovers topology, application programs, parameters and GA
links, but never names, rooms or descriptions, and needs at least ETS Lite.
Or she sniffs the bus for weeks and writes down what each address does.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Recover device tables | `bussard reconstruct --line 1.1 --out house` sweeps a line and synthesises a model with placeholder names. System B in line mode; System 7 is read per device and recorded as a stub in line mode. | BCU1/2 devices come back as stubs. | existing #81 |
| Give GAs names and types | The learn loop runs in chat: the assistant says "press the button", waits with `knx_wait_for_telegram`, calls `knx_infer_group` (ranked DPT candidates, sender, channel, com object, proposed name), confirms with her, and writes the answer with `knx_set_group` and `knx_add_link`. `bussard learn` is the terminal version. | None. | D3 |
| Recover parameters | `bussard backup` reads the raw System B parameter segment; `describe` reads interface objects; import-product gives the parameter schema. | Decoding parameter memory back into the model's `parameters:` block is not offered. | D3 (later) |

### Stage 4. Understand and document

What she does: builds her own mental model. What does the button by the door
do? Which GA is the wind alarm? Which thermostat controls the bathroom? She
wants the button sheet the integrator never wrote.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| See it | `bussard viz` renders the topology, GA tree, live traffic and a Problems panel. `bussard doc` writes the device list, GA list with DPTs and one sheet per room, in Markdown or HTML. | None. | D5 |
| Ask about it | The assistant answers from `knx_project_summary`, `knx_model_lookup`, `knx_get_device`, `knx_recent_telegrams` and `knx_audit`, and explains past changes with `knx_history` and `knx_describe_change`. | None. | D5 |

### Stage 5. Secure ownership

What she does: takes a backup before she changes anything, keeps a copy of
the model off the laptop, changes gateway defaults (some interfaces ship with the web password
"knxnetip"), and decides whether to set a BCU key. CVE-2023-4346 showed that
anyone on the bus can lock unlocked devices with a key, and a set key cannot be
reset, so the KNX checklist recommends setting one and documenting it.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Full backup on day one | `bussard backup` reads every device's tables (and System B parameters) into one snapshot with a manifest; `bussard restore` writes one device back through the `apply` path. `apply` hints when no backup exists. | System 7 parameters are not captured. | D4 |
| Keep history and undo | Built in: every import, apply, flash and MCP model edit is snapshotted under `.bussard/history`. `status`, `history`, `show`, `undo`, and `knx_history`, `knx_describe_change`, `knx_undo` for the assistant. The generated `knx/README.md` leads with history and backups. | None. | D18 |
| Keep a copy elsewhere | `bussard export house.bussard` (or `knx_export_bundle`) writes the model, history and checksum as one file for a USB stick; `apply` reminds her when the export is stale (pending merge). | None. | D19 |
| Gateway and key hygiene | `audit` lists Secure devices and keyring coverage (pending merge). | No check for default gateway credentials, an exposed port 3671, or BCU key status. Setting a BCU key is out of scope until its safety story is written. | D1 |

### Stage 6. Make it hers

What she does: the hallway button should also switch the porch light. The
bathroom heating should drop at night. The blinds should not close on the
terrace when she is having dinner. In ETS this is a five-minute change she
cannot make without a licence and the project file.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Change a link | She says what she wants; the assistant calls `knx_add_link`, which snapshots, validates and returns the sentence ("Outdoor switch actuator, channel C, now listens to Hallway light (1/1/1)."). She confirms in chat, then runs `bussard plan` and `bussard apply` for the device. System B and System 7. | BCU1/2 devices stay ETS-only. | D20, existing #81 |
| Change a parameter | The assistant calls `knx_set_parameter`, checked against the product model; `bussard flash` shows a parameter-level plan ("Night setback: 18 °C to 17 °C") on System B before it writes. | `flash` itself takes no backup; `bussard backup` beforehand covers System B parameters. | D17, D4 |
| Change scenes, timers, setpoints | If exposed as GAs: `bussard write`, or `knx_write_group` with `--allow-writes`. Otherwise parameters, as above. | Same as parameters. | |

### Stage 7. Integrate

What she does: connects Home Assistant. HA needs the gateway address, its own
tunnel, and ideally a project file for names and DPTs, and even then entity
creation is manual. Most ETS projects define GAs without DPTs, which is why
every auto-import tool struggles.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| HA configuration | `bussard ha-config --out ha.yaml` derives covers, lights, switches, sensors and climate entities from com-object flags, with `ha.toml` overrides. `init` and `audit --live` print the tunnel budget, so HA and bussard do not fight for one slot unnoticed (pending merge). | None. | D13 |
| Get her curated names back into ETS | `bussard export-groups --format ets-csv` or `ets-xml` writes a file ETS imports, names, DPTs and descriptions included. | None. | D12 |

### Stage 8. Extend and repair

What she does: adds a presence detector, replaces the blind actuator that died
after eight years. Replacement is the scenario that most often forces an owner
back to an integrator.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Add a device | `bussard adopt --product x.knxprod` assigns an address and writes the device file; the assistant then links it with `knx_add_link` instead of pasted snippets; then `flash`, `plan`, `apply`. | None for System B and System 7. | |
| Replace a device | `bussard replace <ia> --product x.knxprod` checks that the old device is gone and the new one has the same order number and mask, then assigns, flashes with the model's parameters, applies the links and records `replaced:`. | Replacement with a different product. | D6 |

### Stage 9. Keep it healthy

What she does: notices a light that flickers, a blind that sometimes ignores a
command, a bus that feels slow. The usual cause is a GA with a sender and no
listener (three retries per telegram) or a device that stopped acknowledging.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Watch | `monitor`, `capture --to bus.db`, viz Problems panel. `audit --live` samples traffic: repetition rate per GA, GAs sent with no listener in the model, unknown source addresses (pending merge). | No long-term trend across captures. | D1 |

### Stage 10. Exchange with a professional, and hand it on

What she does: hires an integrator for a big change, receives an updated
project file from them, or sells the house. Integrators deliver files, and
they always have: the `.knxproj` is a file handover. She will not open a pull
request and neither will they.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Take an updated file from the integrator | The assistant previews it with `knx_diff_project` and reads the change sentences; `bussard import` merges a `.knxproj` or bundle, keeps her hand-authored names, reports each disagreement as a sentence and exits 3 until settled (pending merge). [collaboration.md](../collaboration.md) documents the exchange. | None. | D19, D7, D16 |
| Send her state to the integrator | `bussard export` or `knx_export_bundle` (pending merge), plus `export-groups` so her names land in their ETS. | None. | D19, D12 |
| Hand a legible package to the next owner | The bundle, the `bussard doc` output and the handover checklist. | A `.knxproj` writer is not planned. | D5, D19, D2 |

## User stories

- As a new owner with a project file, I want one command that tells me how
  complete and how trustworthy it is, so that I know whether to start editing or
  start reconstructing.
- As a new owner without a project file, I want to press each button and have
  the tool name and type the group address it sent, so that a week of evenings
  replaces a 2,000 EUR reconstruction.
- As a new owner, I want a full backup of every device before my first write,
  so that a mistake costs me a restore and not an integrator visit.
- As a new owner, I want a per-room sheet of what every button and channel
  does, so that my family and the next owner can read the house without a
  terminal.
- As a new owner, I want to replace a dead actuator with the same model in one
  guided command, so that a hardware failure does not need a professional.
- As a new owner, I want my assistant's proposed change shown to me in plain
  words, and the device plan before I confirm, so that I stay in control
  without reading the model files.
- As a new owner, I want to undo last Tuesday's change with one command, so
  that a regret costs a minute and not an evening.
- As a new owner, I want my whole configuration as one file I can copy to a
  USB stick or email to an integrator, so that a laptop failure or a
  professional visit never starts from zero.
- As a new owner, I want to load the updated file my integrator sends and keep
  the names I gave things, so that their work and mine add up instead of
  overwriting each other.
- As a new owner, I want to know before I buy an interface how many tunnels it
  has, so that Home Assistant, ETS and bussard can coexist.
- As a new owner, I want my group-address names exported in a format ETS can
  import, so that an integrator I hire later starts from my work.
- As a new owner, I want the tool to refuse the wind alarm and the central-off
  address unless I force it, so that an LLM helping me can never close the
  blinds into a storm.

## What makes bussard the right tool for her, and what is missing

Nadia's operator is her assistant. It connects to `bussard mcp`, reads the
audit, runs the learn loop with her, proposes each change as model edits, and
quotes the sentences those edits return. She never reads the model files or a diff. She
types the commands that program devices (`plan`, `apply`, `flash`) and does
the physical steps (programming buttons, `replace`), because those stay on the
command line behind a confirmation and the real-gateway gate. History and undo
are built in, so a regret costs one sentence to the assistant and one `apply`.

What ships on main: built-in history and undo, the change renderer and the
MCP model-edit tools (D18, D20), learn mode (D3), backup, restore and replace
(D4, D6), the generated house manual (D5), the parameter-level flash plan
(D17), whole-line plan and apply (D8), the ETS group-address export (D12) and
package-manager installs (D14). Pending merge: the audit and the tunnel budget
(D1, D13, D15) and the bundle with its diff (D19, D7). The owner guide, the
handover checklist and the collaboration guide (D2, D16) are written.

What is still missing, in priority order: mask coverage for BCU1/2 devices,
KNXnet/IP Secure (existing #71), a gateway and key hygiene check in the audit,
decoding parameter memory back into the model, and replacement with a
different product.

## Sources

Primary documents were read directly unless marked. Articles on
support.knx.org sit behind a browser challenge and were checked through search
snippets and secondary pages; verify exact wording before quoting them
externally.

- KNX Association, KNX Project Preparation (checklists for implementation,
  handover, security, and "Taking over Software from another Integrator"):
  https://www.knx.es/_data/docsfiles/5_KNX-Project-Preparation_en.pdf
- KNX Toolkit for Professionals:
  https://www.knx.org/knx-en/for-professionals/get-started/toolkit-for-professionals/
- KNX support: project password and Project Password Manager (snippet):
  https://support.knx.org/hc/en-us/articles/360011660999-Project-Password
- KNX support: BCU key (snippet):
  https://support.knx.org/hc/en-us/articles/360011662319-BCU-Key
- KNX support: missing ETS project file (snippet):
  https://support.knx.org/hc/en-us/articles/360018993739-Missing-ETS-project-file
- CISA advisory ICSA-23-236-01, CVE-2023-4346 (BCU key lockout):
  https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01
- Limes Security, KNXlock case study: https://limessecurity.com/en/knxlock/
- ABB, Working with KNX Secure (FDSK stickers, keyring):
  https://library.e.abb.com/public/05b261587e544a1a83e2ef8685bf07cc/Working-with-KNX-Secure_EG_EN_V1-0_9AKK108471A3031_Rev_A.pdf
- IT GmbH, ETS Reconstruction app: https://it-gmbh.de/en/knx/ets-apps/reconstruction/
- MyKNX shop, ETS6 licences: https://my.knx.org/en/shop/ets
- ETS6 FAQ: https://www.knx.org/news/ets6-frequently-asked-questions
- Home Assistant KNX integration: https://www.home-assistant.io/integrations/knx/
- Helge Klein, integrating Home Assistant with KNX:
  https://helgeklein.com/blog/how-to-integrate-home-assistant-with-knx-ets/
- Ivory Egg, KNX over IP (tunnel limits):
  https://ivoryegg.co.uk/essential_guides/a-guide-to-using-knx-over-ip
- knx.org, best practices for group address structures:
  https://www.knx.org/news/tricks-trade-best-practices-knx-group-address-structures
- knx-user-forum, "Eigentum KNX Projektdatei":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/989227-eigentum-knx-projektdatei
- knx-user-forum, "Übergabe ETS-Projektdatei an Kunden und Gewährleistung":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/1168786-%C3%BCbergabe-ets-projektdatei-an-kunden-und-gew%C3%A4hrleistung
- knx-user-forum, "KNX Newbie ohne Projektdatei":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/1911795-knx-newbie-ohne-projektdatei
- knx-user-forum, "Vorhandenes Projekt auslesen" (reconstruction quotes):
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/1702843-vorhandenes-projekt-auslesen
- knx-user-forum, "Umstellung auf KNX Secure":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/2007954-umstellung-auf-knx-secure
- knx-user-forum, MDT IP interface default web password:
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/1139910-mdt-knx-ip-interface-und-default-passwort-f%C3%BCr-webzugriff
- openHAB community, "Jackpot: KNX by accident":
  https://community.openhab.org/t/jackpot-knx-by-accident/133692
- Home Assistant community, KNX GA import discussion:
  https://community.home-assistant.io/t/knx-integration-import-of-group-addresses/714066
- Home Assistant community, repeated telegrams not acknowledged:
  https://community.home-assistant.io/t/knx-repeated-telegrams-not-acknowledged/544138
- elektrikforum.de, refusal to hand over program files:
  https://www.elektrikforum.de/threads/verweigerung-der-programmdateien-von-meiner-bus-knx-anlage.29704/
- OLG Zweibrücken 7 U 51/14 on electrical plans for new-build purchasers:
  https://www.anwalt.de/rechtstipps/muss-ein-bautraeger-den-erwerbern-eines-neubaus-elektroinstallationsplaene-herausgeben_156405.html
- xknxproject (MIT parser for .knxproj): https://pypi.org/project/xknxproject/
