# Persona: Nadia, the new owner

Nadia has just taken the keys to a house with a KNX installation she did not
plan. The installation works, mostly. She wants to know what she owns, make it
behave the way her family lives, connect it to the smart-home platform she
already uses, and never be locked out of her own walls. She can install
software and follow a terminal tutorial, and she talks to an LLM assistant
daily. She has never used git, does not want to learn it, and will not read a
YAML diff to decide whether a change is safe. She is not an electrician and has
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
| A checklist of what to demand | Nothing. No doc mentions handover. | A one-page handover checklist an owner can attach to a purchase or acceptance protocol. | D2 |

### Stage 1. Day one: what is in the cabinet?

What she does: opens the distribution board, photographs labels, finds the
power supplies, looks for a KNXnet/IP interface. Many 2010s houses have only a
USB or serial interface, so the first purchase is often an IP interface. If one
exists she needs its IP address and, on newer gateways, its tunnelling
password.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Find the gateway | `bussard init` discovers gateways by multicast and writes `bussard.yaml`. | Discovery does not report the number of tunnelling slots or whether Home Assistant already holds one. Nothing tells her that a Secure-only interface is refused. | D1, D13 |
| Know what devices exist | `bussard scan 1.1` lists every responding device with mask, manufacturer and order number, and flags devices missing from the model. | A scan of an unknown house takes minutes per line and has no "save what you found" step; the result is lost unless piped to JSON. | D1 |
| Know what bussard can manage | The mask table in SAFETY.md. | She has to cross-reference masks by hand. The scan should say per device "bussard can plan/apply this" or "ETS only". | D1 |

### Stage 2. Import what she was given (scenarios A and B)

What she does: runs the import, types the project password, looks at the
result.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Turn the project into something legible | `bussard import house.knxproj` handles password-protected ETS6 exports and produces named GAs, devices with rooms, links and parameters. `bussard viz` shows the house by floor and room. `bussard validate` lists problems. | The import summary is a line of counts. She needs a readiness report: how many GAs have a DPT, how many devices are unnamed, which devices are Secure, which masks bussard cannot write, whether the project used a BCU key. | D1 |
| Handle the keyring | `bussard keyring house.knxkeys` inspects the export; `--keyring` unlocks tool access on `describe`, `apply`, `flash`. | Nothing checks that the keyring matches the devices in the model, or warns which secured devices have no key. KNXnet/IP Secure interfaces are unsupported. | D1, existing #71 |
| Compare the file to the house (scenario B) | `bussard scan` shows devices not in the model; `bussard plan <ia>` diffs a device's live tables against the model one device at a time. | No installation-wide "does the file match the house" run. A whole-line plan would tell her at once how stale the file is. | D8 |

### Stage 3. Reconstruct from the bus (scenario C)

What she does: with no project file she has two tools. ETS with the paid
Reconstruction app recovers topology, application programs, parameters and GA
links, but never names, rooms or descriptions, and needs at least ETS Lite.
Or she sniffs the bus for weeks and writes down what each address does.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Recover device tables | `bussard reconstruct --line 1.1 --out knx` sweeps a line and synthesises a model with placeholder names. System B (mask 07B0) only; other masks become stubs. | Older houses are full of System 7 (0705) and BCU1/2 devices that come back as stubs. Names and DPTs are placeholders. | existing #81, D3 |
| Give GAs names and types | `bussard monitor` decodes traffic; unknown GAs show as raw hex until a DPT is added. Over MCP, `knx_wait_for_telegram` supports "press the button now". | Naming 300 GAs is a manual loop: press, watch, edit YAML. A learn mode should run that loop, infer the DPT from payload length and value range, propose a name from the sending device and channel, and write the YAML. | D3 |
| Recover parameters | `bussard describe` reads interface objects; import-product gives the parameter schema. | Reading back parameter memory into the model is not offered. Parameters stay ETS or Reconstruction territory. | D3 (later) |

### Stage 4. Understand and document

What she does: builds her own mental model. What does the button by the door
do? Which GA is the wind alarm? Which thermostat controls the bathroom? She
wants the button sheet the integrator never wrote.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| See it | `bussard viz` renders the topology, GA tree, live traffic and a Problems panel (unlinked objects, GAs without sender or listener). | No printable output. The house manual per room (each button, each channel, each GA it touches) can be generated from the model but is not. | D5 |
| Ask about it | MCP tools `knx_project_summary`, `knx_model_lookup`, `knx_get_device`, `knx_recent_telegrams` let an LLM answer "what does 2/1/7 do". | Fine as is. The gap is on the documentation side. | D5 |

### Stage 5. Secure ownership

What she does: takes a backup before she changes anything, puts the model in
git, changes gateway defaults (some interfaces ship with the web password
"knxnetip"), and decides whether to set a BCU key. CVE-2023-4346 showed that
anyone on the bus can lock unlocked devices with a key, and a set key cannot be
reset, so the KNX checklist recommends setting one and documenting it.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Full backup on day one | `apply` backs up the one device it touches to `captures/backups/`. `reconstruct --line` reads tables but writes a model, not a restorable backup. | No `bussard backup` that snapshots every device's tables before the first write, and no restore from such a snapshot. | D4 |
| Keep history and undo | History exists only if she puts the model directory in git. The generated `knx/README.md` opens with what to commit. | She is not a git user. bussard needs its own history: a snapshot on every import, apply, flash and model edit, `bussard history` to list them, `bussard undo` to restore. Git stays optional on top. | D18 |
| Keep a copy elsewhere | Copying the directory. | A single-file bundle (`bussard export house.bussard`) she can put on a USB stick in the cabinet, the way integrators do with ETS exports. | D19 |
| Gateway and key hygiene | Nothing. | A hygiene section in the audit: default credentials reachable, port 3671 exposed, BCU key status per device (readable without key or not). Setting a BCU key is out of scope until the safety story for it is written. | D1, D2 |

### Stage 6. Make it hers

What she does: the hallway button should also switch the porch light. The
bathroom heating should drop at night. The blinds should not close on the
terrace when she is having dinner. In ETS this is a five-minute change she
cannot make without a licence and the project file.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Change a link | Edit `links.yaml`, `bussard plan 1.1.4`, `bussard apply 1.1.4`. Confirmed, backed up, verified. An LLM over MCP proposes the edit; she reviews the diff and runs plan and apply herself. | The review step is a YAML diff, which she will not read. The pending change needs a plain-language rendering ("Rocker 1 on the hallway button will also switch the porch light") in the CLI and in viz before `plan` runs. System B only. | D20, existing #81 |
| Change a parameter | Edit `parameters:` in the device file, `bussard flash <ia> --product x.knxprod`. Product data downloads by order number through the pointer index. | `flash` has no backup and no per-parameter diff; the plan shows memory, not "night setback 18 to 17 degrees". A parameter-level plan would make this safe for an owner. | D17, D5 |
| Change scenes, timers, setpoints | If exposed as GAs: `bussard write`. Otherwise parameters, as above. | Same as parameters. | |

### Stage 7. Integrate

What she does: connects Home Assistant. HA needs the gateway address, its own
tunnel, and ideally a project file for names and DPTs, and even then entity
creation is manual. Most ETS projects define GAs without DPTs, which is why
every auto-import tool struggles.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| HA configuration | `bussard ha-config --out ha.yaml` derives covers, lights, switches, sensors and climate entities from com-object flags, with `ha.yaml` overrides. | Solid. Owners need the tunnel-budget warning: HA and bussard on a one-tunnel interface fight. | D13 |
| Get her curated names back into ETS | Nothing. Import is one-way. | An ETS-importable GA export (CSV or XML) lets a later integrator load her names and DPTs instead of retyping them. | D12 |

### Stage 8. Extend and repair

What she does: adds a presence detector, replaces the blind actuator that died
after eight years. Replacement is the scenario that most often forces an owner
back to an integrator.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Add a device | `bussard adopt --product x.knxprod` assigns an address, writes the device file and prints link snippets; then `flash`, `plan`, `apply`. | Good for System B. Snippets must be pasted by hand. | |
| Replace a device | Assign the old address, `flash` the same application, `apply` the model links. Three commands, each with its own confirmation, and nothing checks that the new device is the same product. | A guided `bussard replace <ia>` that verifies order number and application, flashes, applies, verifies, and reports. | D6 |

### Stage 9. Keep it healthy

What she does: notices a light that flickers, a blind that sometimes ignores a
command, a bus that feels slow. The usual cause is a GA with a sender and no
listener (three retries per telegram) or a device that stopped acknowledging.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Watch | `monitor`, `capture --to bus.db`, viz Problems panel. | No rollup: repeated-telegram rate per GA, senders with no listener seen in traffic, devices that never answer a scan. | D1 |

### Stage 10. Exchange with a professional, and hand it on

What she does: hires an integrator for a big change, receives an updated
project file from them, or sells the house. Integrators deliver files, and
they always have: the `.knxproj` is a file handover. She will not open a pull
request and neither will they.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Take an updated file from the integrator | `bussard import new.knxproj` merges: generated data follows ETS, her hand-authored names and descriptions are kept, disagreements are reported. | The merge exists but is invisible. It needs a plain-language conflict report and a place in the owner guide as the default exchange path. | D19, D2 |
| Send her state to the integrator | Copying the directory. | `bussard export house.bussard` as the one file to email, plus the GA export (D12) so her names land in their ETS. | D19, D12 |
| Hand a legible package to the next owner | `viz` in a browser. | The bundle (D19), the generated documentation (D5) and the handover checklist (D2). A `.knxproj` writer is not planned. | D5, D19 |

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
  without reading YAML.
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

Today bussard already covers the two moments that matter most: it turns a
password-protected `.knxproj` into a readable model in seconds, and it lets her
change links and parameters without ETS, behind a plan and a confirmation. The
MCP server means her assistant can explain the house and propose changes.

Two assumptions in the current design do not hold for her. History is git, and
review is a YAML diff. Both work for the project's authors and fail for the
owner. bussard should own its history (snapshots, `history`, `undo`, D18),
exchange as a single file (D19), and render pending changes in plain language
(D20), with git as an optional layer for people who already use it.

The other missing pieces are, in priority order: an audit that tells her what
she has and what bussard can do about it (D1), an owner onboarding guide and
handover checklist that do not mention git (D2), a learn mode for houses
without a file (D3), a full backup (D4), generated documentation (D5), guided
replacement (D6), the tunnel budget (D13), and package-manager installs so that
"download a binary and verify a checksum" is not the first thing she reads
(D14). Behind all of these sits mask coverage: until `apply` and `reconstruct`
handle System 7, a fair share of houses from the 2000s and 2010s are read-only
for bussard.

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
