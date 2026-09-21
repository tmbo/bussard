# Persona: Jonas, the KNX integrator

Jonas runs a three-person electrical business and is a certified KNX Partner.
He delivers eight to twelve KNX houses a year, plus service work on houses he
or others built. ETS Professional on a dongle is his main tool, Gira X1 his
default visualisation, Excel his room book. His margin lives in the hours
between "cabinet wired" and "customer signed the acceptance protocol", and in
how many change requests he can absorb without a site visit.

## Profile

| | |
|---|---|
| Situation | Quotes, plans, parameterises and commissions KNX for private builders and small commercial jobs. Typical house: 60 to 120 devices, two to four lines, one IP interface or router, Secure on the IP side only. |
| Skills | KNX Basic Course, years of ETS. Reads a group monitor fluently. Scripts nothing; the tools he has offer no scripting. Uses Windows because ETS does. |
| Budget | Pays 1,000 EUR per ETS seat, several hundred per ETS app (Reconstruction, Split & Merge), and bills 30 to 60 EUR per square metre for planning and programming. Every hour on site not billed to a change order is lost. |
| Fears | A customer editing the project and blaming him under warranty. Losing a project file or password. A firmware-mismatched replacement device that wipes parameters. Bricked devices from a bad download. |
| Success | Commissioning day is one pass, the acceptance protocol is generated rather than typed, and the three-month follow-up visit is a remote session. |

A second, adjacent persona is the electrician without KNX certification who
installs easy-mode systems (Hager KNX easy, Gira One) and never opens ETS. He
is not described here; bussard's value for him is the same as for the owner.

## Journey map

### Stage 1. Requirements: the room book and function list

What he does: walks the customer through the KNX checklist. Room by room:
usage, lighting plan, shading, safety, third-party systems (heat pump, PV,
pool), operating philosophy ("left on, right off, central functions at the
bottom"). The KNX guidelines put the result in a separate room book that ETS
references by position number such as "E05-01". The tool for this is Excel;
forum users share home-grown sheets with GA generators because "nothing exists".

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Capture rooms and functions in a form the rest of the pipeline reads | The YAML model has `location.{floor,room}` per device and free-text GA names. | No device-free planning stage. A rooms-and-functions file that generates a GA plan is missing. | D11 |

### Stage 2. Planning: topology, power, devices

What he does: one line per floor, one power supply per line, at most 64
devices per segment and at most 90 percent fill in residential, a spare line
when in doubt. Chooses products, checks bus current. Larger clients (the City
of Frankfurt's KNX rule set is a public example) additionally demand a full
building structure in ETS, defined bus-voltage-failure behaviour per device,
priorities set, and cable lengths documented.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Catch topology mistakes before the download | `bussard validate` checks the model for structural errors (missing DPTs, dangling links, duplicate keys). | No topology lints: devices per line, individual-address ranges, bus current per line versus the power supply (`.knxprod` carries the device's bus current), Secure devices on non-Secure couplers. | D10 |

### Stage 3. ETS project setup: naming and group addresses

What he does: sets up the GA structure. Two conventions dominate. The KNX
guidelines and public clients use main group = floor, middle group = trade,
sub-group in fixed blocks (five per light: on/off, dim, value, feedback,
feedback value; ten per blind; ten per heating zone). Many residential
integrators invert it: main group = function, middle group = floor. knx.org's
own advice is that the structure matters less than consistent GA sets. He
labels every device by trade, room and sequence (`LD_E05_01`) identically in
the plan, the schematic and ETS, and keeps the ETS project log on.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Generate the GA plan from the room book | Nothing. | A scaffold that turns rooms and functions into `groups.yaml` following a chosen convention, with the reserved blocks and gaps the guidelines recommend. | D11 |
| Enforce the convention across the project | `validate` has no notion of a scheme. | Configurable convention lints: block sizes, feedback GA pairing, naming pattern, unused reserved addresses. | D10 |
| Version the project | `bussard import` twice into a git repo yields a textual diff of everything ETS exported. ETS itself offers restore points, "compare versions" on import, and since 6.4 an auto-archive on close; the ETS5-only Project Comparison app does not run on ETS6. | Import into git is a workaround, not a workflow. A direct `bussard diff a.knxproj b.knxproj` and a documented "ETS with git" practice would make bussard the missing diff tool for ETS6. | D7 |

### Stage 4. Bench work: individual addresses and labels

What he does: before install, programs the individual address into each device
on the office desk and writes it on the device, because "some device will get
the wrong address on site and the search begins". Sixty devices means sixty
programming-button presses, each followed by a download in ETS and a label.
The handover checklist requires every device and push-button to be labelled
with its address.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Assign addresses fast | `bussard assign 1.1.7` sets the address of the device in programming mode and verifies it. `bussard adopt` wraps it with product data and a device file. | One device per invocation, each with its own confirmation. Nothing verifies the pressed device is the product the model expects at that address. No label output. | D8 |
| Pre-load applications on the bench | `bussard flash <ia> --product x.knxprod` downloads the application from vendor data; System B and System 7 supported. | Per device, per command. A bench mode that walks the model's device list, prompts for each programming button, assigns, flashes, applies and prints the label would compress an afternoon into an hour. | D8 |

### Stage 5. Commissioning on site: the download pass

What he does: with addresses set, downloads the whole project over the IP
interface in one pass. ETS performance over tunnelling is a recurring
complaint, as is a misconfigured routing versus tunnelling setup that makes
programming "extremely slow". Tunnelling needs a spare individual address per
connection.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Write the whole installation | `plan` and `apply` per device; `apply` is System B only. | No `apply --line` or `plan --line`. A resumable whole-line pass with a summary table (done, skipped: unsupported mask, failed: retry) is what commissioning day needs. | D8 |
| Coexist with ETS on the same interface | Documented tunnel-contention warning in DESIGN.md. | bussard should report the interface's tunnel count at `init` and refuse politely when none is free, instead of timing out. | D13 |
| Mask coverage | System B for tables; System B and System 7 for flash. | Any BCU1/BCU2 or System 7 device in the cabinet is ETS-only for links. Coverage decides whether bussard can be the commissioning tool or only a companion. | existing #81 |

### Stage 6. Functional test and acceptance

What he does: the KNX checklist's functional check: every light, dimmer and
blind, central off, scenes, window contacts, weather station reactions,
third-party interfaces, room-controller calibration. Then the acceptance
protocol per DIN 18015-4, signed twice. Today this is a clipboard. There is no
tool that runs the same test twice, so the three-month follow-up and every
change request are tested by hand or not at all. ETS's Device Compare app
checks that installed devices match the project; nothing checks that the
installation behaves.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Scripted acceptance test | `bussard write` and `bussard read` exist; a shell loop can chain them. | A test file (write this GA, expect that GA to report this value within two seconds; press this button, expect this) with a pass/fail report that becomes the acceptance protocol. Repeatable at the follow-up visit and after every change. | D9 |
| Protected functions during test | `protected: true` GAs need `--force`. | Right default. The test runner needs an explicit allow-list for wind alarm and central-off tests. | D9 |

### Stage 7. Documentation and handover

What he does: assembles the folder the guidelines prescribe: principle scheme,
revised schematics and plans, revised room book, acceptance and test
certificates, description of logic functions, manuals, and the project data
itself if requested (Swiss 2024 guidelines: must be handed over). Public
clients require an addressing list (individual and group addresses) and a
function description, and some forbid password protection on the delivered
file. Integrators describe the button documentation as a Word file with
pictures copied "1:1 from ETS", and dread redoing it after every change.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Generate the documentation from the model | Nothing beyond `viz` in a browser. | `bussard doc` producing device list with addresses, order numbers and locations, GA list with DPTs, per-room button and channel sheets, gateway details, all regenerated after every change. This is the same document the owner needs. | D5 |
| Export for the customer's ETS | Nothing. | GA export in ETS-importable CSV or XML so names and DPTs curated in bussard land in the customer's project. | D12 |
| Handover checklist | Nothing. | A handover doc that lists what to deliver, mirroring the KNX checklist. | D2 |

### Stage 8. After-sales: change requests and remote support

What he does: the customer calls three months in: "the button by the terrace
door should also close the blinds". Remote access is VPN or a vendor
remote-access box; exposing port 3671 is "a massive security risk". Warranty is
the sore point: if the customer edits the project himself, who is liable? The
integrator answer today is a contract clause, a sealed envelope with the
password, and screenshots of the delivered state.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Absorb small changes without a visit | If the customer runs bussard, the change is a diff to `links.yaml`. `plan` shows the device delta. | A documented workflow where owner and integrator share one model repository, changes arrive as pull requests, `plan --json` runs in CI, and the integrator approves without touching the bus. This also answers the warranty question: git history shows who changed what. | D16 |
| Know the delivered state | The git commit at handover is the delivered state. | Needs to be stated in the handover guide, and the acceptance test (D9) rerun after every merged change. | D2, D9 |
| Real-gateway gate | Every write to a non-loopback gateway needs `--allow-remote-gateway` or the environment variable. | Correct for owners. For a professional who only ever writes to real gateways, the environment variable in the shell profile is the intended answer; document it. | D2 |

### Stage 9. Repairs and device replacement

What he does: replaces a failed actuator. ETS's "Replace Device" keeps links
only if the application program is compatible; "Change Application Program"
wipes parameters and links. A Secure replacement with a new FDSK triggers "the
device is secured with a key unknown to this project" and a five-step
workaround.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Replace with the same product | `assign`, `flash`, `apply` in sequence. | A guided `bussard replace` that checks order number and application, offers the model's parameters, flashes, applies, verifies. | D6 |
| Replace with a different but similar product | Nothing. | Channel-level mapping between two applications. Later. | D6 (later) |

### Stage 10. KNX Secure

What he does: IP Secure on the interface, Data Secure rarely ("there is
practically no demand, nobody wants to pay the surcharge"). Where used: scan the
FDSK QR code per device, ETS replaces it with a tool key, export the keyring for
the visualisation. A lost project password is unrecoverable unless the Password
Manager was enabled.

| Need | bussard today | Gap | Issue |
|---|---|---|---|
| Work on a Secure installation | Data Secure tool access via `--keyring` or `--tool-key` on `describe`, `apply`, `flash`; `bussard keyring` inspects an export. KNXnet/IP Secure is not implemented. | IP Secure tunnelling is the one Secure feature integrators actually deploy; without it bussard cannot reach a Secure-only interface at all. FDSK commissioning is further out. | existing #71 |

## User stories

- As an integrator, I want to turn the room book into a group-address plan
  that follows my convention, so that the ETS project starts consistent instead
  of becoming consistent after cleanup.
- As an integrator, I want a diff between two versions of an ETS project, so
  that I can see what changed since handover before I touch a device under
  warranty.
- As an integrator, I want to walk the cabinet with a laptop, press each
  programming button, and have the tool assign, flash, link and label the
  device, so that bench day takes one hour instead of one afternoon.
- As an integrator, I want to plan and apply a whole line in one resumable
  run with a summary, so that commissioning day is one pass.
- As an integrator, I want to write the acceptance test once and run it at
  handover, at the three-month visit, and after every change request, so that
  I sign the protocol on evidence.
- As an integrator, I want the device list, the GA list with DPTs and the
  per-room button sheets generated from the model, so that documentation stops
  being a Word file I redo after every change.
- As an integrator, I want to export GA names and DPTs in a format ETS
  imports, so that bussard and ETS share one vocabulary.
- As an integrator, I want customers' change requests to arrive as reviewable
  diffs with a device-level plan attached, so that I can approve remotely and
  the history shows who changed what.
- As an integrator, I want the tool to tell me which devices in a cabinet it
  can commission and which remain ETS-only, so that I plan the day correctly.
- As an integrator, I want a guided replacement that refuses a mismatched
  product or application, so that a replacement never wipes a customer's
  parameters.

## What makes bussard the right tool for him, and what is missing

For Jonas, bussard is a companion to ETS before it is a replacement. Its
strengths today are the ones ETS lacks: a textual, versioned, diffable model;
a scriptable CLI; an LLM interface; and ETS-free downloads for System B and
System 7 devices. The parts that would change his week are, in order: batch
commissioning (D8), scripted acceptance tests (D9), generated documentation
(D5), the ETS diff (D7), the shared-repository workflow for change requests
(D16), topology and convention lints (D10), and the GA export back to ETS
(D12). Two platform facts bound all of it: `apply` is System B only, and
KNXnet/IP Secure is unsupported, so a cabinet with older actuators or a
Secure-only interface keeps him in ETS regardless.

## Sources

Primary documents were read directly unless marked. Articles on
support.knx.org sit behind a browser challenge and were checked through search
snippets and secondary pages; verify exact wording before quoting them
externally.

- KNX Association, KNX Project Preparation (three checklists):
  https://www.knx.es/_data/docsfiles/5_KNX-Project-Preparation_en.pdf
- KNX Association, KNX Project Design Guidelines (topology, GA blocks,
  labelling, documentation folder, handover of project data):
  https://ivoryegg-au-production-images.s3.amazonaws.com/site_files/30_KNX-Project-Design-Guidelines_en.pdf
- KNX Swiss, Projektrichtlinien 2024:
  https://www.knx.ch/wAssets/docs/publikationen/KNX_Projektrichtlinien_2024_DE_WEB-144dpi.pdf
- KNX Swiss, Planungshilfe und Projekttool:
  https://www.knx.ch/knx-ch/publikationen/knx-swiss-planungshilfe-und-projekttool.php
- City of Frankfurt, quality requirements for KNX/EIB (public-client rule set):
  https://energiemanagement.stadt-frankfurt.de/Betriebsoptimierung/Gebaeudeautomation/Qualitaetsanforderungen-und-Richtlinien-fuer-den-Einsatz-von-KNX.pdf
- DIN 18015-1:2020: https://www.dinmedia.de/en/standard/din-18015-1/320242977
- RAL-RG 678 equipment levels: https://www.hea.de/themen/elektroinstallation/ral-rg-678
- ETS 6.4.0 release notes (multi linking, auto backup, room and function
  columns): https://support.knx.org/hc/en-us/articles/31061986226450-ETS-v6-4-0
- ETS project comparison (snippet):
  https://support.knx.org/hc/en-us/articles/5281726647954-Project-comparison
- IT GmbH, Project Comparison app (ETS5 only):
  https://it-gmbh.de/en/knx/ets-apps/project-comparison/
- KNX support, Split & Merge (snippet):
  https://support.knx.org/hc/en-us/articles/115001821930-Split-Merge
- KNX support, Device Compare (snippet):
  https://support.knx.org/hc/en-us/articles/360022136799-Device-Compare
- KNX support, change and update application program (snippet):
  https://support.knx.org/hc/en-us/articles/360022260019-Change-Update-Application-Program
- KNX support, group address export (snippet):
  https://support.knx.org/hc/en-us/articles/360022237580-Group-Address-Export
- KNX support, advantages of becoming a KNX Partner (snippet):
  https://support.knx.org/hc/en-us/articles/360020923139-Advantages-of-becoming-a-KNX-partner
- KNX Hub, commissioning checklist before handover:
  https://www.knxhub.com/knx-commissioning-checklist-before-handover/
- KNX Hub, AI in KNX commissioning and troubleshooting:
  https://www.knxhub.com/ai-knx-commissioning-troubleshooting/
- smart-home-feeling.de, group address structures:
  https://smart-home-feeling.de/ratgeber/programmierung/knx-gruppenadressen-verstehen
- smart-home-feeling.de, KNX IP and KNX Secure (remote access):
  https://smart-home-feeling.de/ratgeber/vernetzung/knx-ip-und-knx-secure
- elektro.net, secure remote access for KNX:
  https://www.elektro.net/120267/sicherer-fernzugriff-fuer-knx/
- e-necker.at, ETS project file and warranty (integrator view):
  https://www.e-necker.at/knx-projektdatei/
- Piesco, KNX single-family house costs:
  https://www.piesco-automation.de/knx-einfamilienhaus-kosten
- knx-user-forum, "Erstinbetriebnahme der Anlage in der Praxis" (bench addressing):
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/1695184-erstinbetriebnahme-der-anlage-in-der-praxis
- knx-user-forum, "Strategie physikalische Adresse":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/1296114-strategie-physikalische-adresse
- knx-user-forum, "Tastsensor Dokumentation an Kunden übergeben":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/1483389-tastsensor-dokumentation-an-kunden-%C3%BCbergeben/page3
- knx-user-forum, "KNX Elektroplanung Tool Raumbuch und Verteilerschrank":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/1485570-knx-elektroplanung-tool-raumbuch-und-verteilerschrank
- knx-user-forum, "KNX Secure Gerätetausch":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/knx-einsteiger/1794824-knx-secure-ger%C3%A4tetausch
- knx-user-forum, "Data Secure" (demand and vendor support):
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/1806185-data-secure
- knx-user-forum, "VPN Fernzugriff für Wartung":
  https://knx-user-forum.de/forum/%C3%B6ffentlicher-bereich/knx-eib-forum/1406634-vpn-fernzugriff-f%C3%BCr-wartung
- knx-user-forum, Home Assistant subforum, converting .knxproj to HA config:
  https://knx-user-forum.de/forum/projektforen/home-assistant/2026744-ets-knxproj-dateien-automatisch-in-homeassistant-config-umwandeln
- XKNX knx-frontend discussion on project import and conventions:
  https://github.com/XKNX/knx-frontend/discussions/50
- Nordic Semiconductor, KNX IoT on Thread: https://www.nordicsemi.com/Products/Thread/KNX-IoT
- KNX Association, KNX Secure and the Cyber Resilience Act:
  https://www.knx.org/news/security-smart-homes-buildings-knx-and-cyber-resilience-act
