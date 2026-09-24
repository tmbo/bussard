# TOML instead of YAML for the model files

Status: exploration, September 2026. Not implemented. No backwards compatibility
is needed; the project is new.

## The problem with YAML

The model is edited by humans and by an LLM over MCP. YAML types plain scalars
by their spelling, so the writer must know when to quote:

```yaml
ranges:
  '0':          # unquoted 0 is an integer key
    name: UG
  0/0:          # fine, a slash makes it a string
    name: Beleuchtung schalten
groups:
  0/0/1:
    dpt: '1.001'    # unquoted 1.010 becomes the float 1.01
parameters:
  a12-betriebsart@MD-3_M-18_MI-1_P-14_R-14: '2'   # values are strings by contract
product:
  mask: 07B0      # 0705 would need quotes, 07B0 does not
location:
  floor: '1'      # a floor named 1 needs quotes, a floor named DG does not
```

The loader parses to a `serde_norway::Value` first (for duplicate-key
detection) and then into the typed structs. An unquoted `0` or `1.001` fails
loudly there ("invalid type: integer, expected a string"), so this is not
silent corruption. It is friction: the quoting rule depends on the spelling of
the value, the emitter and the human disagree about when quotes are needed, and
every LLM edit has to get it right. Names like `Null`, `~`, `yes` or `1` are
further traps that exist only because YAML guesses types.

## What TOML changes

- Keys are always strings. `0 = { name = "UG" }` and `"0" = ...` mean the same
  thing. The range problem above disappears.
- Values are explicitly typed by syntax. A string is always quoted, a number
  never is. The rule does not depend on what the text looks like.
- Duplicate keys are a parse error in the spec, so the `Value` pre-pass goes.
- `toml_edit` round-trips comments and formatting. Hand comments in the
  user-owned zone survive a save, which `serde_norway` cannot offer. MCP edits
  can touch one line and leave the rest byte-identical.
- Parse errors carry spans. The `toml` crate prints rustc-style carets.

The prototype checked each claim with `toml = "1"` and `toml_edit = "0.25"`
(both MIT OR Apache-2.0, crates.io). Findings:

| Case | Result |
|---|---|
| `0 = { name = "UG" }` under `[ranges]` | key deserializes as the string `"0"` |
| `138 = { ... }` under `[com_objects]` into `BTreeMap<u16, _>` | works, the crate parses integer keys |
| two `138 =` entries | `duplicate key` with a caret at the second one |
| `dpt = 1.010` into a `String` field | `invalid type: floating point \`1.01\`, expected a string` |
| `flgas = "CWU"` | `unknown field \`flgas\`, expected one of \`dpt\`, \`flags\`, \`ref\`, \`channel\`` |
| edit one name with `toml_edit`, add one GA | comments, ordering and untouched lines preserved |

Note the float case: the error text already shows `1.01`, the trailing zero is
gone. That is why floats must be rejected in string fields, never coerced.

## Round 0: mechanical translation

One `[table]` per entity:

```toml
[ranges."0"]
name = "UG"

[groups."0/0/1"]
name = "Licht Büro aussen Schalten"
dpt = "1.001"
```

Every GA header is quoted, and every entity costs three or four lines. The real
`groups.yaml` (1326 lines) becomes 1762 lines, `links.yaml` as arrays of tables
(`[[links."1.1.2"]]`) goes from 1941 to 2704 lines. Correct, but worse to read
and diff than YAML. Rejected.

## Round 1: one line per entity

Keyed inline tables under one header. The key is the address, the value is the
entity:

```toml
imported_from = "home_test.knxproj"

[ranges]
0 = { name = "UG" }
"0/0" = { name = "Beleuchtung schalten" }
"0/1" = { name = "Jalousie" }

[groups]
"0/0/1" = { name = "Licht Büro aussen Schalten", dpt = "1.001" }
"0/0/2" = { name = "Licht Büro aussen Status", dpt = "1.001" }
"0/3/1" = { name = "Heizung Büro Soll", dpt = "9.001", protected = true }
```

```toml
[links."1.1.2"]
21 = { name = "VO 1 - Input", listen = ["0/3/6"] }
36 = { name = "VO 2 - Input", listen = ["0/3/26"] }
334 = { name = "RTC - Input", send = "0/3/2" }
338 = { name = "RTC - Input", listen = ["4/0/0"] }
```

Line counts on the real model:

| File | YAML | TOML round 1 |
|---|---|---|
| groups | 1326 | 451 |
| links | 1941 | 620 |
| device 1.1.4 (24-gang actuator) | 447 | 191 |
| device 1.1.47 | 56 | 37 |

Properties:

- One entity per line, so `grep '"0/0/1"'` finds the definition, a diff of a
  rename is one line, and an LLM edit is a single-line replacement.
- The object number in `links` becomes the key instead of an `object:` field,
  so two links to the same com-object are a parse error instead of a validation
  rule.
- GA keys must be quoted because `/` is not a bare-key character. Forgetting the
  quotes is a parse error with a caret, never a type change.
- Inline tables are single-line in TOML 1.0. A GA with a long `description`
  makes a long line. The emitter can fall back to a `[groups."0/0/1"]` block
  for entries above a width limit; the parser accepts both forms.

## Round 2: taking the quotes out of keys entirely

TOML dotted keys nest tables, and digit-only bare keys are legal, so the KNX
hierarchy can be the table hierarchy:

```toml
[groups.0]
name = "UG"

[groups.0.0]
name = "Beleuchtung schalten"

[groups.0.0.1]
name = "Licht Büro aussen Schalten"
dpt = "1.001"
```

Ranges and groups become one tree and no key anywhere needs quotes. It parses.
Rejected anyway:

- `0.0.1` reads as a version or a float, not as a KNX address. Every KNX
  document, ETS screen and bus monitor writes `0/0/1`.
- A middle-group table holds both `name` and child tables, which needs a custom
  deserializer (`flatten` and `deny_unknown_fields` do not combine).
- It is back to three lines per GA (1762 lines).

The same trick is a trap for device addresses. `[links.1.1.47]` is legal TOML
and means the nested tables `links` > `1` > `1` > `47`. The prototype's error
for it is `unknown field \`1\``, which is loud but misleading. Round 3 handles
it.

## Round 2b: parameters

Today's keys are `<name>@<ref-id>`, and `@` forces quotes. Replacing the `@`
with a dot turns the name into a table and the ref-id into a bare key:

```toml
[parameters.a12-betriebsart]
MD-1_M-1_MI-1_P-14_R-14 = "1"
MD-1_M-2_MI-1_P-14_R-14 = "1"
MD-1_M-3_MI-1_P-14_R-14 = "1"

[parameters.regenalarm]
P-19_R-38 = "1"
```

No quotes in any key. The 24-gang actuator's 12 copies of each parameter sit
under one heading instead of interleaving alphabetically. The in-memory type
stays `BTreeMap<String, String>` keyed `name@ref`; only the file shape changes.

## Round 3: making it fail safe

The parser already rejects the mistakes. These rules make the rejection
helpful or remove the chance to make the mistake.

1. **Strings that look like numbers.** `dpt`, `mask`, `order_number`,
   `floor`, and parameter values are strings. A custom deserializer for these
   fields turns `invalid type: floating point` into
   `dpt must be a quoted string, write dpt = "1.010"`, using the error span to
   quote the source text rather than the parsed float.
2. **Parameter values accept int, bool and string.** `= 2`, `= true` and
   `= "2"` all normalize to the string the parameter model expects. Floats are
   rejected with the rule 1 message, because `1.10` and `1.1` would collide.
3. **Emit bare keys when legal, quoted otherwise.** `0`, `138`, channel and
   ref ids are bare. GAs and device addresses are quoted. The reader can write
   `"0"` or `0` and get the same key.
4. **Detect the dotted-address trap.** If a table under `links` has an all-digit
   key whose value is a table, report
   `[links.1.1.47] nests tables; write [links."1.1.47"]`. The alternative is to
   remove device-address headers altogether by moving each device's links into
   its device file under a `[links]` table, where the address is already a
   value. That is a layering change, not a format change, and is out of scope
   here, but TOML makes it natural.
5. **Format-preserving writes.** Load with `toml` into the typed model. Save
   through `toml_edit`: parse the existing file, apply the changed entities,
   write back. Comments and hand formatting in the user zone survive re-import
   and MCP edits. The generated zone below the marker is rewritten wholesale as
   today.
6. **Keep `deny_unknown_fields`.** The `expected one of` list in the error is
   the fix-it hint.

## Round 4: identity as a value, never as a key

Feedback on rounds 1 to 3: `[links."1.1.47"]` and `"0/0/1" = { ... }` do not
look good. Both put a KNX address in key position, and TOML can only spell
that with quotes. The way out is to make the address a value. TOML allows a
multi-line array of inline tables, so this stays one line per entity:

```toml
imported_from = "home_test.knxproj"

ranges = [
  { address = "0",   name = "UG" },
  { address = "0/0", name = "Beleuchtung schalten" },
  { address = "0/1", name = "Jalousie" },
]

groups = [
  { address = "0/0/1", name = "Licht Büro aussen Schalten", dpt = "1.001" },
  { address = "0/0/2", name = "Licht Büro aussen Status",   dpt = "1.001" },
  { address = "0/3/1", name = "Heizung Büro Soll",          dpt = "9.001", protected = true },
]
```

```toml
[[links]]
device = "1.1.2"
objects = [
  { object = 21,  name = "VO 1 - Input", listen = ["0/3/6"] },
  { object = 334, name = "RTC - Input",  send = "0/3/2" },
]
```

Device files keep top-level scalars and `[location]`, `[product]`,
`[parameters.<name>]` as in round 2b, and the generated zone becomes
`com_objects = [ { object = 138, dpt = "1.005", flags = "CWU", ref = "..." }, ... ]`.

No key in the whole model needs quotes any more. Verified with the prototype:

- Parses into `Vec<Group>` and `Vec<DevLinks>` with `deny_unknown_fields`.
- `dpt = 1.010` inside an element and a misspelt `adress` both get a caret on
  the offending token inside the line.
- A multi-line `"""..."""` string is legal inside an inline table in TOML 1.0,
  so a long `description` does not force a different shape.
- `toml_edit` edits one element and preserves comments and the alignment of
  the untouched lines. Appending an element needs explicit decor handling to
  land on its own line; that is emitter work, not a format limit.
- Real model: groups 453 lines, links 740 lines (the `[[links]]` header costs
  three lines per device).

What moves: uniqueness of `address`, `device` and `object` is no longer a
parse error, it becomes a validation diagnostic like the cross-file rules
that already exist. Column alignment is cosmetic; the emitter pads, an LLM
edit will not, and a save re-formats.

This replaces rounds 1 and 2 in the recommendation.

## Folding links into device files

`links.toml` groups links by device and each device already has a file whose
`address = "1.1.47"` is a value. Folding means `links.toml` disappears and each
device file gains a user-owned `links = [ ... ]` array (or the `send`,
`listen` and `name` fields join the com-object entries, with the generated
fields below the marker). Effects:

- No device address ever appears in key position, which is why it came up in
  round 3. Round 4 solves that without folding.
- A device's wiring and its parameters are read and edited in one file.
- Reviewing "what changed on the bus" needs a diff over `devices/` instead of
  one file. Reassigning a GA that several devices use touches several files.
- The `bussard import` merge rules stay the same: links are imported but user
  owned, com-objects are regenerated.

It is a defensible layout either way. It is a separate decision from the
format and is not needed for the format switch.

## Error messages

22 mistakes a human or an LLM plausibly makes in the round 4 shape were run
through `toml::from_str` with strict structs. Every error comes with a
rustc-style caret on the offending token. 15 need nothing more than a
fix-it suffix; 7 are misleading as they stand and need a hint layer.

**Good as they come** (caret on the right token, message says what to do):

| Mistake | Raw message |
|---|---|
| `,` missing between two elements | `missing comma between array elements, expected \`,\`` (caret on the next element) |
| `address: "0/0/1"` (YAML habit) | `missing assignment between key-value pairs, expected \`=\`` |
| `name = Licht Büro`, `address = 0/0/1` | `string values must be quoted` |
| second `groups = [` block appended | `duplicate key` on the second `groups` |
| `[[groups]]` mixed with `groups = [` | `duplicate key` |
| element without `name` | `missing field \`name\``, caret spans the element |
| `protected = "true"` | `invalid type: string "true", expected a boolean` |
| `listen = "0/3/6"` | `invalid type: string "0/3/6", expected a sequence` |
| `object = "21"` | `invalid type: string "21", expected u16` |
| `dpt = 1.001` | `invalid type: floating point \`1.001\`, expected a string` |
| `address = "0/1"`, `"0/9/1"` | our own `FromStr` text, e.g. `group address \`0/9/1\` is out of range (main 0-31, middle 0-7, sub 0-255)` |
| `[group]` instead of `groups` | `unknown field \`group\`, expected one of \`imported_from\`, \`ranges\`, \`groups\`, \`links\`` |
| newline inside an inline table | accepted (the crate implements TOML 1.1) |

**Misleading, need a hint:**

| Mistake | Raw message | What bussard adds |
|---|---|---|
| `}` missing at the end of an element | `missing key for inline table element, expected key`, caret on the next `{` | `help: the entry starting on line 2 is not closed; add \`}\` before the \`,\`` |
| `]` missing before the next table | `missing comma between array elements`, caret on an unrelated line | `help: the array \`groups\` opened on line 1 is never closed; add \`]\` after its last entry` |
| `"` inside a name unescaped | `missing comma between key-value pairs`, caret after the inner quote | `help: escape it as \`\"\` or use a literal string: name = 'Licht "Süd"'` |
| `name = ,` (empty value) | `invalid literal string, expected \`'\`` | `help: \`name\` has no value; write name = "..." or remove the field` |
| `- { ... }` (YAML list marker) | `missing comma between array elements` | `help: TOML arrays have no \`-\` markers; remove the \`-\`` |
| curly quotes `“0/0/1”` | `string values must be quoted` | `help: “ ” are not quotes in TOML; use straight "0/0/1"` |
| `duplicate key` | names neither the key nor the first definition | primary label on the second, secondary label `first defined here` on the first, `help: add the new entries inside the existing array` |

The layer is small. `toml::de::Error` exposes `message()` and `span()`, so
the loader keeps the caret and appends `help:` lines chosen by a table of
rules over the message plus local context: the character under the caret,
whether the previous line ends in `,` with an unbalanced `{`, bracket balance
from the array's opening line to the caret, and for `duplicate key` a scan for
the earlier definition. Type mismatches get a concrete fix-it line
(`protected = true`, `listen = ["0/3/6"]`, `object = 21`, `dpt = "1.001"`),
and `unknown field` gets `did you mean \`groups\`` by edit distance over the
expected list. All of this lives in `bussard-model` next to the existing E-code
diagnostics and prints through the same rustc-style renderer and `--format json`,
so an MCP tool returns the same text the CLI prints and the model can apply the
fix verbatim.

Two rules move from the parser to `validate` because the address is now a
value: a duplicate `address` in `groups`, and a duplicate `object` under one
device in `links`. Both get two labels (both occurrences) via the `toml_edit`
spans of the elements.

The 22 inputs become snapshot tests (`tests/diagnostics/*.toml` with the
expected rendering) so a `toml` crate upgrade that rewords a message shows up
in CI rather than in front of a user.

## Who edits the device file

The device file has two zones. Below the `GENERATED` marker (`module_bases`,
`com_objects`) nobody edits; re-import rewrites it. Above it, every field is
user-owned, and the edits that happen in practice are:

| Edit | Today's path | Frequency |
|---|---|---|
| name, floor, room | MCP `knx_set_device`, or by hand | at setup, then rarely |
| parameter value already in the file | MCP `knx_set_parameter` (checked against the product model) | the everyday configuration change |
| parameter not yet in the file | by hand only; the MCP tool refuses | whenever a setting still sits at the vendor default |
| description, channel names, product fields | by hand | rare |

So yes: the device file is edited, and `parameters` is its main edit surface.
It is the equivalent of the ETS parameter dialog. The com-object list is not
an edit surface at all; links live in `links.toml`.

That shapes the TOML layout. The user zone comes first and stays short. The
parameter section is where a writer needs the most help:

```toml
[parameters.a12-betriebsart]
MD-3_M-18_MI-1_P-14_R-14 = "2"

[parameters.regenalarm]
P-19_R-38 = "1"
```

Two additions make adding a parameter by hand fail safe. Both need the
product model in `models/`, which E016 and E017 already require:

1. **Ref optional when unambiguous.** `regenalarm = "1"` under
   `[parameters]` is accepted when the product model has exactly one ref for
   that name. When it has several, the diagnostic lists them:
   `regenalarm has 12 refs on this device; write [parameters.regenalarm] and
   one of MD-1_M-1_MI-1_P-7_R-7, ...`. The emitter always writes the full form.
2. **Enum values by label.** Where the product model defines an enumeration,
   accept the label as well as the code (`"Jalousie"` for `"2"`) and normalize
   to the code on save. E017 lists the valid labels when neither matches.

Whether `bussard flash` writes the changed parameters is unchanged: the file
edit is a plan, `apply` and `flash` are the bus operations.

## Round 5: one file is edited, the other is generated

Feedback: a file should be either fully user-owned or fully generated. The
device file today mixes both zones behind a comment marker. Splitting it is
the right call, with one constraint that decides where the generated half
goes: `models/` is gitignored (vendor data is never redistributed), so a
checkout without `.knxprod` files must still validate links, plan, decode
telegrams and derive Home Assistant entities. The com-object table with its
DPTs, flags and channel membership, and the module base offsets, are what make
that possible. They have to stay committed. They just do not have to share a
file with what the user maintains.

```
knx/
  bussard.toml
  groups.toml
  links.toml
  devices/1.1.47.toml               user-owned, every line
  generated/devices/1.1.47.toml     written by import, never edited
  models/                           local only, vendor data
```

`.gitattributes` marks `generated/** linguist-generated=true`, so GitHub folds
those diffs in a pull request while they stay reviewable on demand. `import`
creates the user file once and merges into it afterwards; it overwrites the
generated file every time. A device whose generated file is missing or older
than its user file gets a validation diagnostic that says to re-import.

The user file:

```toml
address = "1.1.47"
name = "Jalousieaktor Kind 2"
description = "Fenster"

[location]
floor = "DG"
room = "Kind 2 Süd"

[product]
order_number = "230021SU"
application = "M-0004_A-20DE-22-C7D8-O000A"

[channels]
"Relaisausgänge 1/2" = { }          # user-facing name per channel, see below

[parameters]
regenalarm = "Ja"

[parameters."Relaisausgänge 1/2"]
betriebsart = "Jalousie"
zuordnung-regen = "Ja"
```

The generated file:

```toml
# generated by `bussard import` from home_test.knxproj; do not edit.
address = "1.1.47"

[product]
manufacturer = "Albrecht Jung"
manufacturer_ref = "M-0004"
mask = "07B0"

channels = [
  { number = 1, id = "MD-3_M-18_MI-1_CH-25", text = "Relaisausgänge 1/2" },
]

[module_bases]
MD-3_M-18_MI-1 = 2915

com_objects = [
  { object = 138, dpt = "1.005", flags = "CWU", ref = "O-138_R-13" },
  { object = 144, dpt = "1.008", flags = "CWU", ref = "MD-3_M-18_MI-1_O-2-0_R-38", channel = 1 },
]

parameter_refs = [
  { key = "regenalarm",                     ref = "P-19_R-38" },
  { key = "Relaisausgänge 1/2/betriebsart", ref = "MD-3_M-18_MI-1_P-14_R-14" },
]
```

`product` splits along the same line: order number and application program
are the user's statement of what the device is and are the join key into
`models/`; manufacturer and mask are looked up from there and land in the
generated file. `security` stays in the user file. Channel *ids* are generated,
channel *names* are the user's.

## Do we need `MD-3_M-18_MI-1_P-97_R-154`?

As identity, yes. As something the user types, no.

The ref id is the only handle that is unique per device and that the flasher
can turn into a memory address. The schema note explains why the parameter
name alone fails: module devices instantiate the same parameter once per
channel, and vendors reuse names across channels. Measured on the 28 devices
with parameters in `knx/devices/` (270 stored values):

| | count |
|---|---|
| module parameters (one per channel instance) | 137 |
| plain parameters | 133 |
| name unique within its channel instance | 255 |
| name repeated within one scope | 15, all on non-module devices |

The 15 collisions are things like `min` under three outputs of an 8-fold
actuator, `wind` for two thresholds of a weather station, and
`treppenhaus-freigabe` under two outputs. ETS shows every one of them under a
distinct heading: Channel, then ParameterBlock, then the parameter. That tree
is in the `.knxprod` Dynamic section, and the importer already reads
`ParameterBlock` membership (`ParameterRefRef`) for com-objects. Extending it
to parameters gives every ref a **path** of vendor texts, with `{{Arg}}`
placeholders resolved as the channel names already are.

The user-file key is then the shortest path that is unique on this device:

| Situation | Key |
|---|---|
| unique on the device | `regenalarm` |
| module parameter | `[parameters."Relaisausgänge 1/2"]` then `betriebsart` |
| reused across ETS channels | `[parameters."Ausgang 1"]` then `min` |
| reused across blocks in one channel | `[parameters."Wind"."Schwellwert 1"]` then `wind` |
| still ambiguous (not seen in this data) | `wind@R-2263` as the escape hatch |

Rules:

- The reader accepts any path that resolves to exactly one ref. Ambiguity is
  E016 with the candidate paths spelled out; an unknown path lists the
  parameters that exist under that heading.
- The emitter writes the shortest unique form, so the file stays as flat as
  the device allows.
- Values accept the enum label (`"Jalousie"`) or the code (`"2"`), an integer
  or a bool, and normalize to the code on save. E017 lists the valid labels.
- `parameter_refs` in the generated file records the resolution for every
  stored value, so `validate`, `plan` and `viz` read the user file without
  `models/`. Adding a parameter and `flash` need `models/`, exactly as E016,
  E017 and `flash` do today.

What this costs: the importer keeps the Dynamic tree (channel number and
text, block text, parameter membership), the product model file grows a
`paths` table, and `knx_set_parameter` gains lookup by path. What it risks:
vendor texts are localized and can change between application versions, so a
re-import after an application upgrade may rename a heading. Ref ids can be
renumbered by the vendor too, so this is not worse than today, and the
re-import merge reports both kinds of drift the same way.

The channel handle is the one open choice. Keying parameter tables by the
channel's user-facing name reads best and matches ETS and the `viz` UI, but a
rename by hand must touch the headers too (the MCP rename tool does it, and a
stale header is E-coded with the current names listed). Keying by ETS channel
number (`[parameters.channel-1]`) is rename-proof and uglier. The samples
above use the name.

## Round 6: a lock file, and a channel-centric device file

Feedback on round 5: generated files should look different from user files
(as in Cargo, uv, Poetry, Yarn), links belong in the device file if there is
one per device, `application` looks like something nobody should have to
type, and channel names need a stable handle.

### The generated half is a lock file

What the ecosystems that commit generated files have in common:

| | Cargo | uv / Poetry | Yarn | npm |
|---|---|---|---|---|
| user file | `Cargo.toml` | `pyproject.toml` | `package.json` | `package.json` |
| generated file | `Cargo.lock` | `uv.lock`, `poetry.lock` | `yarn.lock` | `package-lock.json` |
| syntax | TOML | TOML | own / YAML-like | JSON |
| first lines | `# This file is automatically @generated by Cargo.` | same idea | `# This file is generated by running "yarn install"` | none |
| shape | flat `[[package]]` list, sorted | flat `[[package]]` list | flat, sorted | nested JSON |
| count | one per workspace | one per project | one | one |
| on conflict | regenerate | regenerate | regenerate | regenerate |

None of them switched syntax to look generated. The signal comes from the
name and extension, the `@generated` header (which GitHub's linguist also
uses to fold the diff), a flat machine-oriented layout, and the rule that the
tool owns the whole file. bussard follows that:

```
knx/
  bussard.toml          connection
  groups.toml           the GA plan
  devices/1.1.47.toml   one user-owned file per device, links included
  bussard.lock          @generated: vendor facts for every device, one file
  models/               local only
```

`links.toml` and `generated/` are gone. `bussard.lock`:

```toml
# This file is @generated by `bussard import`. Do not edit it by hand.
version = 1
source = "home_test.knxproj"

[[device]]
address = "1.1.47"
product = "230021SU"
application = "M-0004_A-20DE-22-C7D8-O000A"
manufacturer = "Albrecht Jung"
mask = "07B0"
channels = [
  { number = 1, id = "MD-3_M-18_MI-1_CH-25", text = "Relaisausgänge 1/2", base = 2915 },
]
objects = [
  { number = 138, dpt = "1.005", flags = "CWU", ref = "O-138_R-13" },
  { number = 144, channel = 1, dpt = "1.008", flags = "CWU", ref = "MD-3_M-18_MI-1_O-2-0_R-38" },
  { number = 146, channel = 1, dpt = "5.001", flags = "CWU", ref = "MD-3_M-18_MI-1_O-2-2_R-4" },
]
parameters = [
  { key = "regenalarm",     ref = "P-19_R-38" },
  { key = "1.betriebsart",  ref = "MD-3_M-18_MI-1_P-14_R-14" },
]
```

One file, one `[[device]]` per device, sorted by address. `validate` compares
each device's `product` in the user file with the lock and reports a stale
lock with the command that refreshes it. A merge conflict in the lock is
resolved by re-running import, as with any lock file. TOML stays the syntax
because it is the same parser and because the three ecosystems above chose
it for exactly this job; the `.lock` name and header do the signalling.
`.gitattributes` adds `bussard.lock linguist-generated=true` for certainty.

### The device file, channel-centric, with its links

ETS itself is organized as device, then channel, then that channel's
parameters and com-objects. The user file mirrors that. The handle for a
channel is its number: the ETS `Channel` element carries a `Number`, and a
module-instantiated channel takes the instance ordinal (`M-1` is
"Relaisausgänge 1/2", `M-2` is "3/4", and so on, as the real actuator files
show). The name is a field, so renaming touches one line and nothing else:

```toml
address = "1.1.47"
name = "Jalousieaktor Kind 2"
product = "230021SU"

[location]
floor = "DG"
room = "Kind 2 Süd"

[parameters]
regenalarm = "Ja"

[links]
138 = { listen = ["4/1/2"] }              # device-level object, no channel

[channel.1]
name = "Fenster Süd"                      # optional; vendor text is in the lock

[channel.1.parameters]
betriebsart = "Jalousie"
zuordnung-regen = "Ja"

[channel.1.links]
144 = { send = "0/1/3" }
146 = { listen = ["0/1/4", "0/2/1"] }
```

- No key needs quotes. Object numbers and channel numbers are bare integer
  keys, parameter names are slugs.
- The com-object `name` that `links.yaml` carried goes to the lock as vendor
  text; an entry may still set `name = "..."` as a user override.
- The question "who listens on 0/1/4" is answered by `grep` over `devices/`,
  by `viz`, or by an MCP query, not by one file anymore. `plan` was always per
  device.
- Parameters under a channel resolve as `<channel>.<name>`; a parameter that a
  vendor repeats across blocks inside one channel nests one level deeper
  (`schwellwert-1.zykluszeit = "2"`), the same shortest-unique-path rule as in
  round 5.

### `application` has a default

Nobody types `M-0004_A-20DE-22-C7D8-O000A` in ETS either; ETS picks the
application program when the product is chosen from the catalogue. The same
split as `Cargo.toml` and `Cargo.lock` applies: the user file states the
product (`product = "230021SU"`, the order number printed on the device), the
lock pins the exact program. Import from ETS pins what the project used. A
device added by hand resolves through `models/` (the `adopt` command already
has this step): one matching program pins directly, several pick the newest
and say so. The user file may set `application = "..."` to override, which is
the exception, not the default, and is the only place that id would ever be
typed.

## Round 7: objects by function, one table per channel

### Where 144 and 146 come from

They are the ETS communication object numbers: the `Nr.` column in the
Group Objects tab, assigned by the vendor's application program, with
module channels numbered from a per-channel base. A user finds them in ETS or
in `bussard.lock`. Nothing in `144 = { send = "0/1/3" }` tells a reader which
object that is, or whether it was the right one. Two things fix that.

**Key objects by what ETS shows, not by number.** ETS displays each object as
`Name` plus `Object Function` (`Text` and `FunctionText` in the vendor XML),
for example "Ausgang 1 - Schalten" / "Ein/Aus" or "Jalousie 1" /
"Langzeitbetrieb". Inside one channel the pair is what a human uses to tell
objects apart, so its slug becomes the key and the lock maps it to the number:

```toml
[channel.1]
name = "Fenster Süd"
langzeitbetrieb.send = "0/1/3"
kurzzeitbetrieb.send = "0/1/5"
status-position.listen = ["0/1/4"]
```

What the data says about uniqueness:

- In the resolved object lists of the devices whose application XML the
  project file carries (35 objects across 6 programs), `Text` alone repeats
  once inside a channel, `FunctionText` alone repeats 8 times, the pair never.
- In the raw application trees the pair repeats often (160 of 2328 objects in
  one ABB program), but a raw tree contains every `choose` branch, and the
  repeats are alternatives that a device never exposes at the same time. The
  resolved set per device, which is what the lock holds, is the one that has
  to be unique.
- The 24-gang Jung actuator's program is not in the project file or in any
  local `.knxprod`, so its per-channel uniqueness is unverified. The design
  does not depend on it: where the pair still collides, the emitter appends
  the number (`status-2`, or the bare number) and the reader always accepts
  the number as a key.

**Let the tool prove the choice.** `validate` already flags a link to an
object the device does not have. Two more rules make a wrong object visible:
the object's DPT in the lock must agree with the GA's DPT in `groups.toml`
(a `1.008` up/down object on a `1.001` switch GA is an error, `5.001` percent
on a `9.001` temperature GA likewise), and an object may only `send` if its
flags allow transmit and only `listen` if they allow write. A `describe` view
(CLI and MCP) lists a channel's objects with number, text, function, DPT and
flags, which is how a writer picks in the first place.

### Parameters and links in one table per channel

Yes. A channel in ETS is one screen with its parameters and its objects, and
the file can be the same:

```toml
[channel.1]
name = "Fenster Süd"
betriebsart = "Jalousie"
zuordnung-regen = "Ja"
fahrzeit = 42
langzeitbetrieb.send = "0/1/3"
kurzzeitbetrieb.send = "0/1/5"
status-position.listen = ["0/1/4"]
```

The value's shape says what a line is: a string, integer or bool is a
parameter, a table with `send`, `listen` or `name` is an object. Parsing goes
through a map of `toml::Value` per channel and classifies each entry against
the lock, so the error for an unknown key can say `channel 1 has no
parameter or object "fahrzeit"; parameters: betriebsart, ...; objects:
langzeitbetrieb, ...`.

Two reserved words: `name` is the channel's display name. Nothing else is
special. A vendor slug that collides with a parameter slug in the same channel
(none in the 541 linked objects and 270 parameters of the real model) is
suffixed by the emitter and resolved by value shape on read. Device-level
parameters and objects that belong to no channel sit in `[parameters]` and
`[links]` at the top level as before, or, for symmetry, in `[channel.0]`;
the samples keep the explicit names.

The device file in full:

```toml
address = "1.1.47"
name = "Jalousieaktor Kind 2"
product = "230021SU"

[location]
floor = "DG"
room = "Kind 2 Süd"

[parameters]
regenalarm = "Ja"

[links]
in-betrieb.send = "4/1/2"

[channel.1]
name = "Fenster Süd"
betriebsart = "Jalousie"
zuordnung-regen = "Ja"
langzeitbetrieb.send = "0/1/3"
kurzzeitbetrieb.send = "0/1/5"
status-position.listen = ["0/1/4"]
```

The lock gains the slug next to each object so the mapping is explicit:

```toml
objects = [
  { number = 144, channel = 1, key = "langzeitbetrieb", text = "Jalousie 1", function = "Langzeitbetrieb", dpt = "1.008", flags = "CWU", ref = "MD-3_M-18_MI-1_O-2-0_R-38" },
]
```

## Round 8: what ETS does that the file did not

The converted heating actuator (`devices/1.1.2.toml` in the example) is
unreadable: `vo-4-input`, nine copies of `"konfiguration-rtr@R-…" = "1"`,
`rtc-2-general-1447.send`. None of that is the format's fault. It is what the
YAML model stores, made visible. ETS shows the same device as six valve
outputs and six room controllers, each with a room name, a few dropdowns and
a short object table. It gets there with five mechanisms, and the file needs
all five.

1. **Vendor texts everywhere.** ETS never shows a parameter name, a ref id or
   an object number as the primary label. It shows the parameter `Text`, the
   enum value `Text`, the object `FunctionText`. All three live in the
   `.knxprod`, none in the ETS project. The example is ugly first of all
   because the Jung product data is not on this machine.

2. **One parameter is one memory cell.** The model keys parameters by
   `ParameterRef`. In the heating actuator, `konfiguration-rtr` has nine refs
   `R-2138 … R-2152` that all point at one parameter, `P-1312`, with one
   `<Memory>` location. There is exactly one value on the device; ETS shows the
   one ref that is currently visible. The file must key by parameter
   (`P-1312`), store one value, and pick the visible ref's value on import.
   The nine lines become one: `konfiguration-rtr = "1"`.

3. **Only what applies is shown.** The six bundled application programs
   contain 18 603 `<choose>` and 31 792 `<when>` elements. A parameter or object
   in a branch whose condition is false does not exist for that device. ETS
   evaluates the tree; import must too, so that a switched-off channel or a
   mode that is not selected contributes nothing to the file. This is the same
   evaluation that mechanism 2 needs to know which ref is visible.

4. **The user's label is the heading.** The room names `WC UG`, `Garage UG`,
   `Diele UG` in the example are not settings. They are the channel labels,
   the `Bezeichnung` text field at the top of each channel page in ETS. ETS
   knows which parameter that is: `Channel`, `ParameterBlock` and
   `ComObjectRef` carry a `TextParameterRefId` pointing at it, and every
   `{{0}}` in their `Text` is replaced by its value (4 593 object refs and all
   35 channels in the bundled programs use it). Import resolves the same
   pointer, writes the value as the channel's `name`, and leaves it out of the
   parameter list. The lock records that `name` maps to `P-1320`.

5. **Channels are named by kind.** ETS counts "Valve output 3" and "Room
   temperature controller 3" separately. A flat `channel.9` hides that. The
   handle is the vendor's short channel `Name` plus its `Number`: `vo-3`,
   `rtc-3`, for the 12-fold actuator `a-1 … a-12` or whatever the vendor
   abbreviates. The full vendor text stays in the lock.

With all five, the same device reads like the ETS dialog does:

```toml
address = "1.1.2"
name = "Heizungsaktor UG"
product = "360061SR"

[location]
floor = "UG"
room = "Technik"

[channel.vo-1]
name = "WC UG"
stellgroesse.listen = ["0/3/6"]

[channel.vo-2]
name = "Garage UG"
stellgroesse.listen = ["0/3/26"]

[channel.rtc-1]
name = "WC UG"
betriebsart = "Heizen"
art-der-heizung = "Stetig PI"
istwert.listen = ["0/3/1"]
sollwert.send = "0/3/2"
betriebsmodus.send = "0/3/3"
stellgroesse-heizen.send = "0/3/4"
status.send = "0/3/9"
```

Parameter texts, enum labels and object functions here are illustrative;
the Jung program is not available locally to confirm the exact words. The
structure is what the five mechanisms produce.

Consequences for the tool:

- **Product data is a prerequisite for a device file with parameters.**
  Without the `.knxprod` there is no text, no enum label, no memory map and
  no way to flash, so import writes the identity, location and links (objects
  by number, marked as such) and reports that parameters were skipped for
  lack of product data. Today's model stores them by ref anyway; that data is
  inert without the product model and is what made the example unreadable.
- **The importer gains the dynamic tree.** Channel `Name` and `Number`,
  `ParameterBlock` nesting, `TextParameterRefId`, and evaluation of
  `choose`/`when` against the imported values. The parser already reads the
  blocks and their `ParameterRefRef` and `ComObjectRefRef` membership; the
  evaluation is new and is the largest piece of work in this whole proposal.
- **The lock changes shape.** Parameters are listed by parameter id with the
  visible ref, channels carry their label ref, objects their function text.
- **Collisions get a page.** When two visible parameters in one channel share
  a text, the `ParameterBlock` text becomes an intermediate table
  (`[channel.rtc-1.sollwerte]`). In the ETS dialog they sit on different
  pages for the same reason.

What remains hard to read is inherent: a room controller has a dozen objects
and ETS shows a dozen rows too. The file has no way around that, but each row
can at least say what it is.

## Two user stories

Both stories use the round 8 layout. Commands that exist today are named as
they are; steps the proposal adds are marked *(new)*.

### Starting with bussard, no ETS

1. `bussard init` finds the gateway and writes `knx/bussard.toml`, an empty
   `groups.toml` and an empty `bussard.lock`.
2. The GA plan comes from rooms and functions, not from addresses.
   `bussard scaffold plan.toml` reserves a block per light, blind and heating
   zone and names every address `<Floor> <Room> <Function> <Role>`. The
   result is `groups.toml`, one line per address, which the owner or the
   assistant edits directly afterwards.
3. Product data first: `bussard import-product --order-number 230021SU`
   downloads the vendor file with confirmation and builds the local
   `models/`. Nothing readable can be written about a device before this.
4. Press the programming button, run `bussard adopt`. It assigns the next
   free address, cross-checks the order number the device reports, and
   writes `devices/1.1.5.toml` with identity, product and location, plus the
   device's `[[device]]` entry in the lock. The device file is short at this
   point: a device at vendor defaults has no parameter lines.
5. Configure by writing the file, by hand or through the assistant over MCP:

   ```toml
   [channel.a-1]
   name = "Küche Decke"
   betriebsart = "Schalten"
   schalten.listen = ["1/0/5"]
   status.send = "1/0/6"
   ```

   To know what a channel offers, `bussard show 1.1.5 a-1` *(new)*, and the
   MCP tool behind it, list the channel's parameters with their choices and
   its objects with function, DPT and flags, the way the ETS page does.
6. `bussard validate` catches an unknown key with the channel's real names,
   an object on a GA of the wrong DPT, a `send` on an object that cannot
   transmit *(new rules)*.
7. `bussard plan 1.1.5` shows the table diff, `bussard apply 1.1.5` writes it,
   `bussard flash 1.1.5` writes the parameters; the program comes from the lock
   *(new: no `--product` flag)*.
8. `git commit` the user files and the lock. `bussard monitor` decodes traffic
   with the names from step 2, `viz` shows the house, `ha-config` derives Home
   Assistant, `claude mcp add knx -- bussard mcp` hands the model to the
   assistant.

The owner never sees a ref id, an object number or an application id. The
first time they see the word "application" is if two programs match an order
number and import says which one it pinned.

### Moving from ETS

1. Export the project from ETS (`.knxproj`). Collect the `.knxprod` for each
   product, either from the ETS catalogue export or with
   `bussard import-product --order-number …` per device. The project file
   bundles only some programs (six of about fifteen in the house used here),
   so this step is not optional.
2. `bussard import house.knxproj` writes `groups.toml`, one `devices/*.toml`
   per device and `bussard.lock`. For a device whose product data is present
   the file reads like its ETS dialog: channel headings carry the room names
   typed into ETS, parameters appear by text with their chosen label, objects
   by function. For a device whose product data is missing, import writes
   identity, location and the links with objects by number and ends with a
   list of order numbers still to fetch *(new)*. After
   `import-product`, running `bussard import` again upgrades those files in
   place; import is idempotent.
3. `git init`, commit, read. Open a device file next to its ETS page. They
   should say the same thing in the same order. `bussard validate` reports
   what ETS tolerated: a GA without a DPT, an object linked to a GA of another
   type.
4. Trust the model against the bus: `bussard plan 1.1.x` for every device
   should show an empty diff, because ETS programmed exactly these tables.
   `bussard monitor` shows the house talking, with names.
5. Living with both for a while is supported. A later ETS export goes through
   `bussard import` again; names, locations and hand edits survive where the
   address is unchanged, and a value changed on both sides is a conflict
   settled with `--mine`, `--theirs` or interactively. The moment ETS is put
   away, the repository is the source of truth: `bussard export` bundles it,
   `bussard doc` renders the handover folder.
6. The first change made in bussard rather than ETS is small on purpose: a
   room renamed in `groups.toml`, a setback temperature changed in a device
   file, `flash`, done. From then on the assistant does most of the typing.

The migration is only as good as the product data. Import without it yields
the file this exploration started from, and the tool should say so on every
run instead of producing it quietly.

## The full example

`docs/toml-exploration/knx/` is the current `knx/` folder converted to the
round 7 layout by `docs/toml-exploration/convert.py`, every file checked with
the `toml` crate. Its README lists what the conversion could derive without
vendor data and what it could not. Read it together with round 8: the
heating actuator there shows exactly what happens without mechanisms 1 to 5.

## Alternatives to TOML for an LLM writer and a human reader

| Format | LLM fluency | Human reading | Typing hazards | Comment-preserving edits in Rust | Verdict |
|---|---|---|---|---|---|
| YAML as today | highest | best for scalars | quotes depend on spelling | none | the current pain |
| YAML, failsafe schema | highest | best | `#` and `: ` inside unquoted values, indentation | none | see below |
| TOML round 4 | high | good, table-like | floats vs strings | `toml_edit` | recommended |
| JSON / JSON5 | highest | poor, no comments in JSON | floats vs strings | none mainstream | rejected |
| HCL | high (Terraform) | good, `group "0/0/1" { }` | floats vs strings, expressions and `${}` templates | `hcl-edit` | plausible, heavier |
| KDL | low | very good, one node per line | v1 vs v2 syntax churn | `kdl` document model | too niche for the writer |

**YAML with the failsafe schema** deserves a sentence because it fixes the
original complaint without changing format. YAML 1.2 defines a schema in which
every scalar is a string, and the struct decides the type. `serde_norway`
already passes the raw scalar text when the target is a `String`; the type
inference only comes from the `Value` pre-pass used for duplicate detection.
Replace that pre-pass with a duplicate scan over the parser events, and `0:`,
`1.001` and `2` need no quotes in files or in the emitter. What it does not
fix: a `#` in an unquoted name silently ends the value (`name: Raum #3`
becomes `Raum`), a `: ` inside a name is a parse error, indentation mistakes
are still possible, and no Rust crate preserves comments through a save.

**HCL** is the closest competitor. The `import, validate, plan, apply` loop is
Terraform-shaped and LLMs write Terraform fluently. `group "0/0/1" { ... }`
puts the address in a label, which HCL quotes idiomatically. Blocks with more
than one attribute must span lines, so a GA costs four lines. `hcl-rs` (MIT)
has serde support and a format-preserving `hcl-edit`. The cost is HCL's
expression language: `name = Licht` parses as a variable reference and
`"${...}"` inside a string is a template. Both fail loudly under strict
deserialization but they are extra rules to teach.

**KDL** is the best syntactic fit on paper (`group "0/0/1" name="Licht"
dpt="1.001"`, one line, no brackets, native nesting) but LLMs have seen little
of it and KDL 2.0 changed the literal syntax in 2024. For a format the model
writes directly, that is the wrong bet.

## What does not get better

- Every name is quoted: `name = "Licht Büro"` versus `name: Licht Büro`. A
  name containing `"` uses a literal string `'...'`.
- Home Assistant users know YAML. The HA config bussard emits stays YAML
  because it is HA's format, so `serde_norway` stays in `bussard-ha`. Only the
  model files, `bussard.toml` and the `ha.yaml` overrides file switch.
- Inline tables cannot span lines in TOML 1.0. Do not rely on the 1.1
  relaxation even though `toml 1.x` supports it; other editors and LLMs
  target 1.0.

## Recommendation

Switch. Use the round 4 shapes (arrays of inline tables, address as a value,
no quoted keys) with the round 2b parameter layout and the round 3 rules.
Uniqueness of addresses and object numbers becomes a validation diagnostic.
Layout as in round 6: `bussard.toml`, `groups.toml`, one user-owned
`devices/<address>.toml` per device with its links, and one `@generated`
`bussard.lock` holding every vendor fact. Channels are keyed by number and hold
their parameters and objects in one table; objects are keyed by the vendor's
name and function, parameters by name; the lock maps both to numbers and refs
and pins the application program.

The switch touches `bussard-model` (`loader.rs`, `schema.rs` key types,
`param_model.rs`), the MCP edit tools in `bussard-mcp`, `import_product_cmd.rs`
in the CLI, `overrides.rs` in `bussard-ha`, the `knx/` fixtures, the test
fixtures, `docs/reference.md` and the README. `serde_norway` leaves every
crate except `bussard-ha`.

The converted real files behind the numbers above are in
`docs/toml-exploration/` (`groups.toml`, `links.toml`, two device files). All
of them parse with the `toml` crate.
