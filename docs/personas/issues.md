# Issue drafts from the persona journeys

Twenty drafts, each traceable to a journey stage in
[homeowner.md](homeowner.md) or [integrator.md](integrator.md). The `D` numbers
are draft identifiers used by the persona docs; they are not GitHub issue
numbers. Drafts were filed on GitHub on 2026-09-21 and 2026-09-22; the table links the
issue. Existing GitHub issues predating the drafts are written `#71`.

Priority reflects how many journey stages a draft unblocks and how far it is
from existing code. P1 drafts compose existing commands; P2 add a subsystem; P3
depend on platform work (mask coverage, Secure) or are planning-stage tooling.

| ID | GitHub | Title | Persona | Priority |
|---|---|---|---|---|
| D1 | [#93](https://github.com/tmbo/bussard/issues/93) | `bussard audit`: installation readiness and health report | both | P1 |
| D2 | [#94](https://github.com/tmbo/bussard/issues/94) | Owner onboarding guide, handover checklist, professional notes | both | P1 |
| D3 | [#95](https://github.com/tmbo/bussard/issues/95) | Learn mode: name and type group addresses from live traffic | owner | P2 |
| D4 | [#96](https://github.com/tmbo/bussard/issues/96) | `bussard backup` and `restore` for the whole installation | both | P1 |
| D5 | [#97](https://github.com/tmbo/bussard/issues/97) | `bussard doc`: generated installation documentation | both | P2 |
| D6 | [#98](https://github.com/tmbo/bussard/issues/98) | `bussard replace <ia>`: guided device replacement | both | P1 |
| D7 | [#99](https://github.com/tmbo/bussard/issues/99) | `bussard diff`: semantic diff of two ETS projects | integrator | P2 |
| D8 | [#100](https://github.com/tmbo/bussard/issues/100) | Batch commissioning: `plan`, `apply`, `assign`, `flash` over a line | integrator | P2 |
| D9 | [#101](https://github.com/tmbo/bussard/issues/101) | `bussard test`: scripted functional acceptance tests | integrator | P2 |
| D10 | [#102](https://github.com/tmbo/bussard/issues/102) | Topology and convention lints in `validate` | integrator | P2 |
| D11 | [#103](https://github.com/tmbo/bussard/issues/103) | `bussard scaffold`: group-address plan from a room and function list | integrator | P3 |
| D12 | [#104](https://github.com/tmbo/bussard/issues/104) | Group-address export in ETS-importable CSV and XML | both | P1 |
| D13 | [#105](https://github.com/tmbo/bussard/issues/105) | Report tunnelling capacity at `init` and refuse cleanly when none is free | both | P1 |
| D14 | [#106](https://github.com/tmbo/bussard/issues/106) | Package-manager installs: Homebrew, winget, `curl \| sh` | owner | P1 |
| D15 | [#107](https://github.com/tmbo/bussard/issues/107) | Documentation consistency: Secure flags, System 7 status, tunnel budget | both | P1 |
| D16 | [#108](https://github.com/tmbo/bussard/issues/108) | Collaboration guide: owner and integrator share one model repository | both | P1 |
| D17 | [#109](https://github.com/tmbo/bussard/issues/109) | Parameter-level plan for `flash` | owner | P2 |
| D18 | [#110](https://github.com/tmbo/bussard/issues/110) | Built-in history and undo, no git required | both | P1 |
| D19 | [#111](https://github.com/tmbo/bussard/issues/111) | `bussard export` and `import` of a single-file bundle | both | P1 |
| D20 | [#112](https://github.com/tmbo/bussard/issues/112) | Plain-language rendering of pending model changes | owner | P1 |

---

## D1. `bussard audit`: installation readiness and health report

Labels: enhancement

Persona: Nadia stages 1, 2, 5, 9; Jonas stage 5.

### Problem

After `import`, `scan` or `reconstruct`, the owner has a model and no idea how
good it is. The import summary is a line of counts. The questions that decide
her next week are unanswered: how many GAs have a DPT, which devices are
unnamed, which devices are Secure and covered by the keyring, which masks
bussard can `apply` to and which stay ETS-only, whether the bus shows repeated
telegrams or GAs nobody listens to, whether the gateway has a free tunnel. The
integrator needs the same list to plan a commissioning day.

### Proposal

A read-only command with a static part (the model) and an optional live part
(the gateway and bus). Text and `--json` output.

Static: device count per line, devices without name or location, GAs without
DPT or name, links to unknown com objects, devices per mask with a "bussard
can: plan/apply, flash, describe, ETS only" column, Secure devices with and
without a matching keyring entry, protected GAs, model version and last import
source.

Live (`--live`, read tier only): gateway description and tunnel count (D13),
scan delta against the model per line, and a traffic sample over a configurable
window with repeated-telegram rate per GA, GAs seen with a sender but no
listener in the model, and devices that never answered. Everything the viz
Problems panel knows should appear here too, so the two stay one code path.

### Acceptance criteria

- `bussard audit` on the synthetic fixture prints a report with every section
  above and exits 0; `--json` emits the same as one object.
- `bussard audit --live` never transmits a group write and respects the rate
  limiter.
- The mask capability column is derived from the same table `plan`, `apply`
  and `flash` use to refuse, so it cannot drift.
- Documented in reference.md and howto.md ("... find out what I have?").

Related: D13, D5, viz Problems panel, #45 (scan probe budget).

---

## D2. Owner onboarding guide, handover checklist, professional notes

Labels: documentation

Persona: Nadia stages 0, 2, 5; Jonas stages 7, 8.

### Problem

No document addresses the person who has just received a KNX house. Nothing
lists what to demand at handover, in which order to run the first commands, or
what to commit. The integrator side has no handover checklist either, and the
real-gateway gate reads as an obstacle to a professional who writes to real
gateways every day.

### Proposal

Three documents under `docs/`:

- `docs/getting-started-owner.md`: "the first weekend". Find the interface,
  `init`, `import` or `scan` plus `reconstruct`, `audit`, `backup`, `viz`,
  `export` a bundle to a USB stick, connect the assistant over MCP, first safe
  change with `plan` and `apply`, `undo` it. Each step names the safety rail
  that applies. The guide does not mention git; a closing note points git
  users at the optional repository layer.
- `docs/handover-checklist.md`: a one-page list an owner can attach to a
  purchase or acceptance protocol and an integrator can use as a delivery list.
  Contents follow the KNX Association handover and security checklists:
  latest `.knxproj` and its password, `.knxkeys` and password, FDSK stickers,
  BCU key if set, gateway IP and credentials, tunnelling addresses, device list
  with individual addresses, GA list with DPTs, as-built plans, acceptance
  report, visualisation credentials, what changed since the last version.
  A short note on the legal position (guidelines say the latest project must
  be handed over; contracts decide; sealed envelope as compromise). For a
  bussard-managed installation, the bundle from D19 and its checksum are the
  delivered state.
- A "for professionals" section in SAFETY.md: the environment variable for the
  real-gateway gate, why it is per machine and not per repository, tunnel
  etiquette when ETS is also connected.

### Acceptance criteria

- README links the owner guide from the Quickstart.
- Every command named in the guide exists and its flags match reference.md.
- The checklist fits one printed page.
- The word "git" does not appear before the closing note of the owner guide.
- The generated `knx/README.md` leads with history and backups, not with what
  to commit.

Related: D1, D4, D16, D18, D19.

---

## D3. Learn mode: name and type group addresses from live traffic

Labels: enhancement

Persona: Nadia stage 3.

### Problem

Without a project file, a house has hundreds of GAs with placeholder names
and no DPT. The only way to name them is to press a button, watch `monitor`,
and edit YAML. `knx_wait_for_telegram` gives an LLM the press-and-watch step,
but nothing closes the loop into the model.

### Proposal

`bussard learn` runs an interactive loop over the model's unnamed or untyped
GAs, or over whatever appears on the bus:

1. Wait for a telegram (optionally prompted: "press the button you want to
   name"). Show sender device, channel and com object from the model, payload
   length and decoded candidates.
2. Infer a DPT candidate set from payload length and value range (1 bit: 1.xxx;
   1 byte with values 0 to 100 or 0 to 255: 5.001 or 5.010; 2 bytes float in a
   plausible temperature range: 9.001; and so on). Rank candidates using the
   sending com object's declared DPT when the device file has one.
3. Propose a name from device location, channel name and function (for
   example "Kitchen ceiling light, switch"). Accept, edit or skip.
4. Write `groups.yaml` and, when the sender is known, the `links.yaml` entry.

Over MCP, expose the inference as a read-tier tool so an assistant can drive
the same loop conversationally; the write into the model stays with the CLI.

Later: read parameter memory back into the device file for System B devices
where the product data is available.

### Acceptance criteria

- On the simulator, a scripted session names and types a set of GAs and the
  resulting model passes `validate` with no W011 warnings for those GAs.
- DPT inference is a pure function with unit tests over the common payload
  shapes and never claims certainty for ambiguous lengths.
- Learn mode never transmits.

Related: #81 (System 7 reconstruct), D1.

---

## D4. `bussard backup` and `restore` for the whole installation

Labels: enhancement

Persona: Nadia stage 5; Jonas stage 8.

### Problem

`apply` backs up the one device it is about to write. `flash` backs up
nothing. There is no way to snapshot every device before the first write, and
no restore command for the backups that do exist. For an owner, a full backup
on day one is the difference between "I can experiment" and "I dare not touch
it".

### Proposal

`bussard backup [--line 1.1 | <ia>...] --out captures/backups/<timestamp>/`
reads the tables (and, for supported masks, the parameter memory that `flash`
would write) of every reachable model device into the existing per-device
backup JSON format, plus a manifest with mask, application identity and read
time. `bussard restore <backup-dir> <ia>` writes one device back through the
same plan, confirm, write, verify path as `apply`. Unsupported masks are listed
in the manifest as skipped, never silently omitted.

### Acceptance criteria

- `backup` never writes to the bus.
- `restore` of a fresh backup onto an unchanged device produces an empty plan.
- On the simulator, `apply`, then `restore` from the pre-apply backup, returns
  the device to byte-identical tables.
- `backup` is a step in the owner guide (D2) and `apply` prints a hint when no
  installation-wide backup exists.

Related: D2, SAFETY.md backups section.

---

## D5. `bussard doc`: generated installation documentation

Labels: enhancement

Persona: Nadia stages 4, 10; Jonas stage 7.

### Problem

The KNX guidelines prescribe a documentation folder: device list with
addresses, GA list, function description, button sheets per room. Integrators
produce it by hand in Word and dread redoing it after every change; owners
rarely receive it. bussard holds everything needed in the model.

### Proposal

`bussard doc --out docs/` renders Markdown (and HTML via the viz templates)
from the model:

- Device list: individual address, name, location, manufacturer, order
  number, application, mask, Secure flag.
- GA list: address, name, DPT, description, protected flag, senders,
  listeners.
- Per room: every device in the room with its channels, and for each channel
  the GAs it sends and listens on, in plain language ("Rocker 1 switches
  Kitchen ceiling light; status from 1/0/12").
- Gateway and connection details from `bussard.yaml` (never credentials).
- A change log from git when the model directory is a repository.

Output is deterministic so it diffs cleanly and can be committed.

### Acceptance criteria

- Runs on the synthetic fixture and on a `reconstruct`ed model with
  placeholder names without failing.
- Deterministic: two runs on the same model are byte-identical.
- The per-room sheet is readable without KNX knowledge (tested by the wording
  guideline in D2's owner guide).

Related: D12, D1.

---

## D6. `bussard replace <ia>`: guided device replacement

Labels: enhancement

Persona: Nadia stage 8; Jonas stage 9.

### Problem

Replacing a failed actuator is the repair that most often forces an owner back
to an integrator. In bussard it is `assign`, `flash`, `apply`, each with its own
confirmation, and nothing checks that the new device is the same product or
application. In ETS, an incompatible application wipes parameters and links.

### Proposal

`bussard replace 1.1.4 --product x.knxprod`:

1. Confirm the old device is absent (no answer) or explicitly `--force`.
2. Prompt for the programming button; read the new device's order number,
   mask and application; refuse on mismatch with the model unless `--force`.
3. Assign the address, flash the application with the model's parameters,
   apply the model's tables, verify, and print a summary.
4. Record the replacement in the device file (`replaced: <date>`) so the
   history shows it.

Later: channel-level mapping when replacing with a similar product of a
different application.

### Acceptance criteria

- Refuses when the pressed device's order number differs from the model.
- On the simulator, replacing a device yields tables byte-identical to a
  pre-failure backup (D4).
- Uses the existing plan, confirm, verify path; no new write primitive.

Related: #79 (flash freshness), D4, D17.

---

## D7. `bussard diff`: semantic diff of two ETS projects

Labels: enhancement

Persona: Jonas stages 3, 8.

### Problem

ETS6 has no textual diff. Restore points and "compare versions" exist; the
Project Comparison app runs on ETS5 only. An integrator taking over a project,
or checking what a customer changed under warranty, has no way to answer
"what differs between these two exports". Importing both into git works but
needs two model directories and reads as a workaround.

### Proposal

`bussard diff old.knxproj new.knxproj` (passwords via the existing flag and
environment variable) imports both into memory and prints a semantic diff:
devices added, removed, renamed, moved; links added and removed per device;
GA names, DPTs and descriptions changed; parameters changed per device with
the human parameter name from product data when available. `--json` for
tooling. `bussard diff knx/ new.knxproj` diffs a model directory against an
export, which is what the re-import merge already computes internally.

Document alongside it the "ETS with git" practice: export after every ETS
session, `bussard import`, commit; the diff is the review.

### Acceptance criteria

- Two exports of the same project produce an empty diff.
- Renaming a GA in ETS shows as one rename, not a delete and an add.
- Reuses the merge report from `bussard-model::merge` rather than a second
  comparison.

Related: D12, D16, #83 (ETS XML layer).

---

## D8. Batch commissioning: `plan`, `apply`, `assign`, `flash` over a line

Labels: enhancement

Persona: Jonas stages 4, 5; Nadia stage 2.

### Problem

Every bus-writing command handles one device. Commissioning sixty devices
means sixty invocations and sixty confirmations, and the bench ritual
(press the button, assign, label) is repeated by hand. Nothing verifies that
the pressed device is the product the model expects at that address.

### Proposal

Two additions.

`bussard plan --line 1.1` and `bussard apply --line 1.1`: iterate the model's
devices on a line, one confirmation for the run, a summary table with per-device
status (applied, unchanged, skipped: unsupported mask, failed: reason) and a
resumable state file so a tunnel drop continues where it stopped. `--json` for
the summary.

`bussard commission --line 1.1`: the bench mode. For each device in the model
without a confirmed address: prompt "press the programming button on
<name> (<order number>)", read the responding device's order number, refuse on
mismatch, assign, optionally flash and apply, verify, then print a label line
(`1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room`) and
append it to a labels CSV.

### Acceptance criteria

- One confirmation per run, naming the gateway; `--yes` for non-TTY.
- A device with an unsupported mask is reported and skipped; the run continues.
- Killing the process mid-run and restarting resumes without re-writing
  finished devices.
- Order-number mismatch is a hard stop for that device.

Related: #81 (System 7 tables), #45, D6.

---

## D9. `bussard test`: scripted functional acceptance tests

Labels: enhancement

Persona: Jonas stages 6, 8; Nadia stage 6.

### Problem

The functional check at handover is a clipboard. The same check is not rerun
at the three-month visit or after a change request because there is no tool
that runs it. ETS Device Compare checks devices against the project, not
behaviour.

### Proposal

A `tests.yaml` in the model directory:

```yaml
tests:
  - name: Kitchen ceiling light switches and reports
    write: { ga: "1/0/10", value: on }
    expect: { ga: "1/0/12", value: on, within: 2s }
  - name: Wind alarm raises the blinds
    manual: "Trigger the wind alarm on the weather station"
    expect: { ga: "3/1/0", value: up, within: 5s }
```

`bussard test` runs the file against the live bus behind the usual write gate,
waits for expected telegrams with the monitor path, and prints a pass/fail
report that `bussard doc` can include as the acceptance protocol. Tests that
touch protected GAs require an explicit `allow_protected: true` in the file and
`--force` on the command line.

### Acceptance criteria

- Runs on the simulator with a fixture test file; failing expectations exit
  non-zero with the observed value.
- Never writes a protected GA without both opt-ins.
- Report is deterministic apart from timestamps.

Related: D5, D16.

---

## D10. Topology and convention lints in `validate`

Labels: enhancement

Persona: Jonas stages 2, 3.

### Problem

`validate` checks structural validity of the YAML. It does not know the
topology rules integrators plan by (64 devices per line, one power supply per
line, bus current against the supply, address ranges) or the GA conventions a
project follows (fixed blocks per function, feedback pairing, naming
patterns). Mistakes surface on the bus.

### Proposal

Warnings, off by default until a scheme is declared in `bussard.yaml`:

```yaml
lint:
  topology:
    max_devices_per_line: 64
    supply_ma: { "1.1": 640 }
  groups:
    scheme: floor-trade-block    # or function-floor
    blocks: { light: 5, blind: 10, heating: 10 }
    feedback_pairing: true
```

Topology lints: devices per line over the limit, sum of device bus current
(from product data) over the declared supply, individual addresses outside the
line, Secure devices behind a non-Secure coupler when the model knows it.
Convention lints: GA outside its block, missing feedback address for a
switching GA, name not matching the pattern, DPT inconsistent with the block
role.

### Acceptance criteria

- No new warnings on existing fixtures when no `lint:` block is present.
- Each lint has a code, a one-line explanation and a fixture that triggers it.
- Bus current values come from `.knxprod` via the existing product cache.

Related: D11.

---

## D11. `bussard scaffold`: group-address plan from a room and function list

Labels: enhancement

Persona: Jonas stages 1, 3.

### Problem

The room book is Excel and the GA plan is typed into ETS by hand. Every
integrator has a home-grown generator because the KNX guidelines describe the
scheme but no tool implements it.

### Proposal

A device-free planning file:

```yaml
rooms:
  - floor: Ground floor
    room: Kitchen
    functions: [light, light-dim, blind, heating]
```

`bussard scaffold plan.yaml --scheme floor-trade-block` writes `groups.yaml`
with the reserved blocks (five per light, ten per blind and heating zone),
names following the labelling convention, DPTs filled, and gaps left for
growth. An LLM over MCP can draft `plan.yaml` from a conversation with the
customer.

### Acceptance criteria

- Output passes `validate` and the D10 convention lints for the chosen scheme.
- Both dominant schemes (floor-trade-block, function-floor) are supported.
- Re-running on an extended plan adds addresses without renumbering existing
  ones.

Related: D10, D12.

---

## D12. Group-address export in ETS-importable CSV and XML

Labels: enhancement

Persona: Nadia stages 7, 10; Jonas stage 7.

### Problem

Import is one-way. Names and DPTs curated in bussard (by an owner naming her
house, or by an integrator's scaffold) cannot reach ETS except by retyping.
ETS imports GAs from its own CSV and XML formats.

### Proposal

`bussard export-groups --format ets-csv|ets-xml --out groups.csv` writes the
GA list with name, DPT and description in the format ETS's Group Address import
accepts. No `.knxproj` writer is planned; this is the bridge.

### Acceptance criteria

- The XML output validates against the ETS group-address import schema; the
  CSV round-trips through `bussard import --from-json` of an xknxproject dump.
- Protected flag and descriptions are preserved in the description field.
- Documented in howto.md ("... get my names into ETS?").

Related: D7, D5.

---

## D13. Report tunnelling capacity at `init` and refuse cleanly when none is free

Labels: enhancement

Persona: Nadia stages 1, 7; Jonas stage 5.

### Problem

A tunnelling interface has a fixed number of connections, often one to five.
Home Assistant, ETS and bussard each need one. When none is free bussard times
out with a generic error, and nothing at `init` tells the owner how many slots
her interface has.

### Proposal

At `init` and in `audit --live`, read the interface's description and
tunnelling DIB (additional individual addresses and, where supported, the
tunnelling info DIB with slot status) and print "N tunnels, M in use". When a
connect fails with `E_NO_MORE_CONNECTIONS`, print a specific message naming the
likely other clients. Document the tunnel budget in SAFETY.md.

### Acceptance criteria

- Against the simulator with a configured tunnel count, `init` prints the
  count.
- The no-more-connections error is distinguished from a network timeout in
  the message and the exit code.

Related: D1, D15.

---

## D14. Package-manager installs: Homebrew, winget, `curl | sh`

Labels: enhancement

Persona: Nadia, before stage 1.

### Problem

The README says package managers are planned. An owner who is not a Rust
developer meets "download a binary and verify a checksum" as the first step.

### Proposal

A Homebrew tap and formula, a winget manifest, and a `curl | sh` installer that
verifies the published `.sha256` before placing the binary. Release workflow
publishes all three from the existing artifacts.

### Acceptance criteria

- `brew install tmbo/tap/bussard`, `winget install bussard`, and the shell
  installer each produce a working `bussard --version` in CI.
- README install section lists them first.

---

## D15. Documentation consistency: Secure flags, System 7 status, tunnel budget

Labels: documentation

Persona: both.

### Problem

Three inconsistencies found while mapping the journeys:

- `docs/reference.md` still states that bussard cannot program a Secure device
  and does not document `--keyring` and `--tool-key` on `flash`, `apply` and
  `describe`, which SAFETY.md and the CLI do support.
- `docs/DESIGN.md` ("The frontier") says System 7 is not flashable, while
  SAFETY.md and reference.md list System 7 masks as supported by `flash`.
- `docs/flash-op-coverage.md` says System B only and predates System 7
  support.

The tunnel budget is mentioned in DESIGN.md constraints but not where an owner
looks (SAFETY.md, howto.md).

### Proposal

Fix the three statements, add a tunnel-budget paragraph to SAFETY.md, and add
a doc-consistency check to CI that greps the mask support table from one
source (the Rust table, rendered) into the docs.

### Acceptance criteria

- The mask support table appears once and is generated or cross-checked.
- reference.md documents every flag `--help` prints.

---

## D16. Collaboration guide: owner and integrator exchange changes

Labels: documentation

Persona: Jonas stage 8; Nadia stage 10.

### Problem

Change requests after handover are the integrator's recurring cost and the
warranty dispute waiting to happen. Both are solved by a shared, legible
history. Most owners are not git users and integrators deliver files, so the
workflow cannot assume a shared repository.

### Proposal

`docs/collaboration.md` with two tracks.

File track, the default. The handover bundle (D19) is the delivered state and
its checksum goes on the acceptance protocol. The owner sends `bussard export`
output or describes the wish; the integrator runs `bussard diff` (D7) against
the delivered bundle to see in plain language what the owner changed, makes the
change in ETS or bussard, and sends back a `.knxproj` or bundle; the owner's
`bussard import` merges it, keeps her hand-authored names, and reports
disagreements. Both sides' `bussard history` (D18) answers who changed what
and when, which is the warranty question.

Repository track, for customers who want it. One repository per installation;
the owner or her assistant proposes changes as pull requests; CI runs
`validate`, D10 lints and `plan --json` against a recorded device state; the
integrator approves; whoever is on site runs `apply`; D9 tests run after
merge.

Both tracks: what never enters a bundle or repository (`.knxproj`,
`.knxprod`, keyrings, passwords).

### Acceptance criteria

- A worked example for each track with the synthetic fixture: one link
  changed, the diff or plan output, the resulting `apply`.
- The file track is the one the owner guide (D2) links to.

Related: D2, D7, D9, D18, D19.

---

## D17. Parameter-level plan for `flash`

Labels: enhancement

Persona: Nadia stage 6; Jonas stage 9.

### Problem

`flash` with edited parameters shows a memory-level plan. An owner changing a
night setback wants to see "night setback: 18 to 17 degrees", not byte offsets.
Without that, parameter changes feel unsafe even when they are.

### Proposal

Before the memory plan, print a parameter diff between the device file and the
current device memory decoded through the product data: parameter name (human
text from the `.knxprod`), old value, new value, unit. Parameters that cannot
be read back are listed as "unknown current value". The memory-level plan
remains available with `-v`.

### Acceptance criteria

- On the simulator, changing one parameter shows exactly one parameter line.
- Decoding uses the existing parameter type tables in `bussard-ets`; no new
  parser.
- Works for System B; System 7 prints the memory plan with a note.

Related: D6, #81.

---

## D18. Built-in history and undo, no git required

Labels: enhancement

Persona: Nadia stages 5, 6; Jonas stage 8.

### Problem

History exists only when the model directory is in git. Owners are not git
users, and "what did I change last Tuesday, put it back" has no answer inside
bussard. Every other tool an owner uses (documents, photos, ETS with its
restore points and since 6.4 an archive on every close) keeps its own history.

### Proposal

bussard owns its history. Every `import`, `apply`, `flash`, `adopt`,
`replace`, `learn` and every model edit made through bussard writes a
snapshot of the model files under `<dir>/.bussard/history/<timestamp>/` with a
manifest: reason (the command and its arguments), gateway if a write happened,
and the result. A house model is well under a megabyte, so snapshots are full
copies with no dependency.

- `bussard history` lists snapshots with reason and a one-line plain-language
  summary of the change (D20).
- `bussard show <n>` renders the change between two snapshots (D7's semantic
  diff).
- `bussard undo [<n>]` restores the model to a snapshot. It changes files only;
  the owner then runs `plan` and `apply` to push the restored model to
  devices, behind the usual gate.
- Edits made outside bussard (an editor, an LLM writing YAML) are captured as
  an "external edit" snapshot at the start of the next command, so nothing is
  lost.

Git stays optional. The history directory is git-ignored by the generated
`.gitignore`, so a git user keeps one history in git and the owner keeps one in
bussard; `undo` reads bussard's.

### Acceptance criteria

- On the synthetic fixture, `import`, edit, `apply` on the simulator, `undo`,
  `plan` shows the reverse of the applied change.
- `history` output is deterministic apart from timestamps.
- Snapshots never contain product data, keyrings or passwords.
- The generated `knx/README.md` explains history and undo before it mentions
  git.

Related: D2, D7, D19, D20.

---

## D19. `bussard export` and `import` of a single-file bundle

Labels: enhancement

Persona: Nadia stages 5, 10; Jonas stages 7, 8.

### Problem

The model is a directory. Integrators deliver files, on a USB stick in the
cabinet or by email, and owners back up by copying files to a stick. A
directory is awkward to email, checksum, or put on an acceptance protocol.
The `.knxproj` has the right shape; bussard's model does not.

### Proposal

`bussard export house.bussard` writes a zip archive containing the model
files, the history (D18) unless `--no-history`, and a manifest with bussard
version, model version, export time, device and GA counts, and a SHA-256 of
the contents. It never includes `vendor/`, `models/`, captures, keyrings or
passwords, and the manifest says so.

`bussard import house.bussard` accepts the bundle wherever a `.knxproj` is
accepted today and runs the same merge: generated data follows the bundle,
hand-authored fields in the local model are kept, disagreements are reported in
plain language (D20) with the choice to take theirs or keep mine per item.
`bussard diff house.bussard` (D7) shows what a received bundle would change
before importing it.

`bussard init` and the owner guide (D2) recommend an export to removable media
as the last step of the first weekend, and `apply` prints a hint when the
latest export is older than the latest apply.

### Acceptance criteria

- Export then import into an empty directory reproduces the model
  byte-identically.
- Import of a bundle over a locally edited model keeps local names and reports
  each disagreement.
- The bundle opens with any zip tool and the manifest is readable JSON.
- No file in the bundle matches the never-commit list in `product-data.md`.

Related: D2, D7, D12, D16, D18.

---

## D20. Plain-language rendering of pending model changes

Labels: enhancement

Persona: Nadia stage 6; Jonas stage 8.

### Problem

Review today means reading a YAML diff. Owners will not read `links.yaml`
hunks to decide whether a change an assistant proposed is safe. `plan` shows
the device-level delta, which is the right last check but is expressed in com
objects and tables.

### Proposal

A renderer that turns a model change (two model states, or the working tree
versus the last snapshot) into short sentences built from device names,
locations, channel names and GA names:

- "Rocker 1 on Hallway push button will also switch Porch light (0/0/4)."
- "Living room blind actuator, channel B, no longer listens to Central down
  (3/0/1)."
- "Night setback on Bathroom thermostat: 18 to 17 degrees."
- "Wind alarm (3/2/0) is protected and is not touched."

Surfaces: `bussard status` (pending changes since the last snapshot, the
default first line before `plan`), `bussard history` and `show` (D18),
`bussard diff` (D7), the import merge report (D19), and a "pending changes"
panel in viz. Over MCP, a read-tier `knx_describe_change` tool so an assistant
can quote the rendering back to the owner before she confirms. The YAML diff
remains available with `--raw`.

### Acceptance criteria

- Golden tests: a fixture of model pairs and the expected sentences; every
  change kind in the model schema has at least one.
- Unknown or unnamed items degrade to addresses, never to an empty sentence.
- `plan` prints the rendering above the table diff when the model differs from
  the last snapshot.

Related: D7, D17, D18, D19.
