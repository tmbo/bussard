# Model commands

The commands that create, import, export, compare, check and document the model directory: `init`, `import`, `export`, `diff`, `validate`, `groups reserve`, `export-groups` and `doc`. None of them writes to a device.

The options every command shares are on [Global options](../global-options.md) and are not repeated here.

## `bussard init [PROJECT]`

Create a fresh model directory: discover the gateway and write the skeleton, then import a project when there is one.

```console
$ bussard init [PROJECT] [--scan <LINE>] [--yes-download | --no-download] [--yes]
```

With a resolved tunnelling gateway, `init` prints what the interface says about itself:

```console
$ bussard init
Gateway: Jung IP Interface (192.0.2.10:3671, IA 1.1.0)
Tunnelling: 4 tunnels, 1 in use.
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `[PROJECT]` | the one `.knxproj` next to `--dir` | The ETS project (a `.knxproj`, or an xknxproject `.json` dump) to import right after writing the skeleton. |
| `--password <PASSWORD>` | | Project password, as for `import`. |
| `--yes-download` | off | Download missing vendor product data without asking. Without a terminal and without this flag nothing is downloaded; the missing order numbers are listed. |
| `--no-download` | off | Do not download missing product data; list it instead. |
| `--scan <LINE>` | | Without a project: scan this line after writing the skeleton, without asking. |
| `--yes` | off | Skip the confirmation prompt for a non-empty directory. |

`--gateway` (or `BUSSARD_GATEWAY`) skips gateway discovery and writes that gateway into `bussard.toml`; `--routing` configures routing instead.

Behaviour:

- The model directory is `--dir`, `BUSSARD_DIR` or the current directory. `init` never searches upward.
- With a project, `init` runs [`import`](#bussard-import-project) right after writing `bussard.toml`, product-data download and validation included.
- Without a project, on a terminal, it offers to scan line 1.1 and list the devices that answer (see [`scan`](devices.md)). `--scan <LINE>` does that without asking. Off a terminal and without flags it writes the skeleton and stops.
- A directory that already holds `bussard.toml` is refused.
- A directory with anything else in it (other than `.git`, `.env`, `.gitignore` and `.bussard/`), or with a model one level down in `knx/`, gets a question first: `the current directory /home/me/house is not empty (12 entries, a model exists in knx/); initialise a model in the current directory? [y/N]`. `--yes` answers it; without a terminal and without `--yes`, `init` refuses.
- In a non-empty directory `init` keeps existing files and adds its `.bussard/`, `*.knxkeys` and `.env` lines to an existing `.gitignore`, each only when missing.
- With a project, `init` looks for an ETS keyring export (`.knxkeys`) in the project's directory. With `BUSSARD_KEYRING_PASSWORD` set, the import merges exactly one into the key store `bussard.keys` (see [`keys`](secure.md#bussard-keys-verb)). Without the password, `init` records it as the deprecated `connection.keyring` (relative to the model directory when it sits next to it, else absolute) and prints the `bussard keys import` command that moves it into the store. Several are listed and none is picked. The password is never written anywhere.
- Gateway discovery is multicast and does not cross subnets. When it finds nothing, `init` still writes a valid skeleton with a placeholder gateway.
- When every tunnel slot is taken, `init` prints the no-free-tunnel message (exit code 4 on [Global options](../global-options.md)) and still writes the skeleton.
- `init` reports KNXnet/IP Secure as `tunnelling is secure-only (needs tunnelling credentials)`, `supported, plain tunnelling allowed` or `not advertised`. A secure-only interface skips the plain reachability check, and `init` names the credentials a command needs. Discovery lists such interfaces as `KNXnet/IP Secure only`.

??? note "Details"
    The interface description is a unicast DESCRIPTION_REQUEST, which uses no tunnel slot. The tunnel count comes from the tunnelling-info DIB (KNXnet/IP Core v2). An interface that sends only its additional individual addresses prints `N tunnels (usage not reported)`; an older interface that reports neither says so. The Secure line comes from an extended search (SEARCH_REQUEST_EXTENDED).

## `bussard import [PROJECT]`

Import an ETS `.knxproj`, a `.bussard` bundle (see [`export`](#bussard-export-file)) or an xknxproject JSON dump into the model, fetch missing product data, then validate.

```console
$ bussard import [PROJECT] [--from-json <FILE>] [--password <PASSWORD>] [--mine | --theirs | --interactive]
```

When product data is still missing, the summary says where to get it:

```console
$ bussard import house.knxproj --dir knx
1 device(s) written without product data: their files carry identity, location and links by number; `apply` writes their links, not their parameters
product data still missing:
  TST-1: not in bussard's product index. Download the product data (.knxprod) from the manufacturer's website (or export it from ETS's catalog), then run `bussard import-product <file> --dir knx`.
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `[PROJECT]` | | The `.knxproj` or `.bussard` file to import. Omit it with `--from-json`. |
| `--from-json <FILE>` | | Import from an xknxproject JSON dump instead of a `.knxproj`. |
| `--password <PASSWORD>` | `BUSSARD_PROJECT_PASSWORD`, then a prompt | Project password. |
| `--mine` | off | On a re-import, keep this model's value for every hand-edited conflict and exit 0. |
| `--theirs` | off | On a re-import, take the incoming value for every hand-edited conflict. |
| `--interactive` | off | On a re-import, ask per conflict (`m` keeps mine, `t` takes theirs). Needs a terminal. |
| `--yes-download` | off | Download missing vendor product data without asking. Without a terminal and without this flag nothing is downloaded; the missing order numbers are listed. |
| `--no-download` | off | Do not look up or download missing product data; list it instead. |
| `--yes` | off | Skip the confirmation prompt for a non-empty directory that holds no model yet. |

Behaviour:

- The model directory is `--dir`, `BUSSARD_DIR` or the current directory; `import` never searches upward. To import into `knx/`, pass `--dir knx` or `cd knx` first.
- A directory that already holds a model is a re-import and asks nothing.
- Any other non-empty directory gets the same question as [`init`](#bussard-init-project): `the current directory /home/me/house is not empty (3 entries); import into the current directory? [y/N]`. Without a terminal and without `--yes` the import is refused and nothing is written.
- An import into a directory without a model writes or merges the same `.gitignore` as `init`.
- Every import into an existing model snapshots it first, so `bussard undo` reverts it.
- After the write, `import` prints what changed in the model as the sentences `bussard status` uses, validates the written model and prints `validation: N error(s), M warning(s)` with each error. An error does not undo the import.
- A group address a device uses but the project does not define is added to `groups.toml` (see [`groups reserve`](#bussard-groups-reserve-floor-room-function)).

**Product data.** After the write, `import` looks up every device's order number that `bussard.lock` does not yet pin in `<dir>/products/` in bussard's pointer index, the one `import-product --order-number` uses.

- The downloads it finds are listed with size and origin and fetched after one confirmation for the whole list (`--yes-download` for scripts).
- Each download is verified against the index checksum, stored under `<dir>/products/`, pinned in the lock and turned into product models under `<dir>/.bussard/models/`.
- An application program no stored archive carries is extracted once from the `.knxproj` into `<dir>/products/<application-id>.knxprod`. See [Product data](../product-data.md).
- A device without product data still gets its file (identity, location, links by number). `apply` writes its links but not its parameters.
- `BUSSARD_PRODUCT_INDEX=<file.json>` points at another index of the same shape.
- A bundle import runs no download step.

**Re-import and conflicts.** Re-import is idempotent.

- The generated sections (com-object tables, link wiring, parameters) always come from the incoming side.
- Hand-authored fields (names, rooms, descriptions, DPTs, `protected`, channel names) that differ are conflicts, printed as sentences: `Group address Light Kitchen (1/0/1): the name is "Light Kitchen" here and "Kitchen ceiling" in the bundle. Kept this model's value.`
- Without a flag the local value is kept and `import` exits `3`. `--mine`, `--theirs` and `--interactive` settle the conflicts and exit 0.
- A device, channel or com object the project no longer has is dropped with its links, and its keys leave the device file. Device files whose address left the project are pruned.
- A send or listen address the local model has and the incoming side lacks is a conflict, because the model records no history for links. `--theirs` removes it, `--mine` keeps it, `--interactive` asks; without a flag it is kept and `import` exits `3`. A stored parameter value that differs is a conflict in the same way.
- With `--theirs`, the device files, `groups.toml` and `bussard.lock` match a fresh import of the same project byte for byte. `bussard.toml` is yours and stays as it is.

**Bundles.** A bundle imported into a directory without a model (no `groups.toml`, no device file) is extracted byte for byte, history included. An existing `bussard.toml`, for example from `init`, is kept. A bundle imported into an existing model runs the merge above; the local history stays and the bundle's snapshots are not merged.

## `bussard export [FILE]`

Write the model and its history as one `.bussard` file: the handover file for an integrator and the owner's backup.

```console
$ bussard export [FILE] [--no-history]
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `[FILE]` | `<parent>/<dir name>-<YYYY-MM-DD>.bussard` | The bundle to write, next to the model directory by default. |
| `--no-history` | off | Leave the `.bussard/history` snapshots out. |
| `--json` | off | Print `{"path", "manifest"}`. |

Behaviour:

- The model must load; `export` refuses a broken model.
- It records the bundle's path, time and model digest in `<dir>/.bussard/last_export.json`.
- After a verified `apply`, bussard prints a one-line hint on stderr when that record is older than the newest `apply` snapshot and the model files changed since, or when the model was never exported. An apply of an unchanged model stays quiet.

The bundle format is on [Model directory](../model-directory.md).

## `bussard diff <A> <B>`

Explain what changes from `A` to `B` as the plain sentences `bussard status` prints. Each side is a `.knxproj`, a `.bussard` bundle, an xknxproject `.json` dump or a model directory. Both are loaded in memory; nothing is written.

```console
$ bussard diff <A> <B> [--raw | --checklist] [--password <PASSWORD>] [--password-b <PASSWORD>]
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `<A>`, `<B>` | | The two sides. |
| `--json` | off | Emit `{"a", "b", "summary", "touches_protected", "changes": [...]}`, the same change objects as `status --json`. |
| `--raw` | off | Print a file-level TOML diff instead of the sentences. |
| `--checklist` | off | Print a per-device Markdown checklist of the changes to redo by hand in ETS. With `--json`, emit the same structure as JSON. |
| `--password <PASSWORD>` | `BUSSARD_PROJECT_PASSWORD` | Password for both `.knxproj` sides. |
| `--password-b <PASSWORD>` | | Password for the second side, when it differs. |

Behaviour:

- Exits 0 whether or not there are differences.
- Group addresses are matched by address and devices by individual address, so a GA renamed in a newer export is one rename, not a removal and an addition. Two exports of the same project give an empty diff.
- A parameter change is named by its text from the product model when a model-directory side has one, else by its key.
- A link sentence names the device with its address: `Meteodata 140 S (1.1.202), channel CH-0, now switches …`.

**`--checklist`.** ETS signs its project files, so bussard cannot write changes back into a `.knxproj`. `bussard diff <export> knx --checklist` prints the work to redo in ETS, in ETS order:

1. *Group addresses*: new, renamed, DPT, description, security, removed, with the range names: `- [ ] 4/1/20 "Aussen dunkel", DPT 1.001, new (main group 4 "Zentral", middle group 4/1 "Wetterdaten")`.
2. One `## <address> <name> (<room>)` section per device, with *Device* (name, location, product, channel names), *Parameters*, *Objects and links* and *Security*. A parameter line gives the ETS page, the ETS label, the new value and the old one: `- [ ] Universalkanal C4: Funktion › Helligkeitsschwelle: unter 20 lx (was über 10000 lx)`. The old value is the vendor default when the old side stores none. A parameter that enables another one's page comes first. An object line shows only the roles that changed: `- [ ] Objekt 105 "C18.1 Logikmodul" (Schalten): sends 1/0/4 (was nothing)`.
3. *Not in ETS by hand*: what ETS does not take (gateway, transport, admission, the `protected` flag), a value stored at its vendor default, and a parameter ETS does not show under the new values.
4. The item count and `Afterwards: export the project and run bussard diff <export> <B>; it should report no changes.`

The pages and old values come from the product models of a model-directory side. A cached model of an older format carries no pages; the checklist says so, and `bussard device <address>` regenerates it.

`--checklist --json` emits `{"schema", "a", "b", "changes", "items", "groups": [...], "devices": [{"address", "name", "room", "device", "parameters", "objects", "security"}], "notes": [...]}`. Each item has `kind`, `text` and, where they apply, `device`, `group`, `object`, `page`, `label`, `value`, `old_value`.

## `bussard validate`

Validate the model and its keys, and report diagnostics. Offline; never prompts.

```console
$ bussard validate
```

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Print `{"schema", "diagnostics": [...]}`; each diagnostic has `code`, `severity`, `message` and `location`. |

Behaviour:

- Exits non-zero on errors; warnings and infos alone exit 0. The codes are on [Diagnostics](../diagnostics.md).
- The key checks (E027 to I031) use the file `BUSSARD_KEYRING` names, else the key store `bussard.keys`, else the deprecated `connection.keyring`.
- It decrypts the keyring once with `BUSSARD_KEYRING_PASSWORD`. Without the password it prints one info line (I031) and skips the key checks.

## `bussard groups reserve "<FLOOR> <ROOM>" <FUNCTION>...`

Reserve the conventional group addresses for one room, append them to `groups.toml` and print them.

```console
$ bussard groups reserve "EG Küche" light blind
reserved 9 group address(es) for EG Küche in knx/groups.toml (floor-trade-block scheme):
  1/1/0     1.001    EG Küche Light Switch
  1/1/3     1.001    EG Küche Light Switch status
  1/2/0     1.008    EG Küche Blind Move
  ...
```

The room is one argument, floor first: the first word is the floor, the rest the room. Each function gets the block of its trade, five addresses for a light and ten for a blind or a heating zone. Every address is named `<Floor> <Room> <Function> <Role>` with its DPT; unused slots in the block stay free for growth.

Functions: `light` (switch and feedback), `light-dim` (switch, dim, value, both feedbacks), `blind`, `heating`, `socket`.

| Flag | Default | Meaning |
|---|---|---|
| `--scheme <SCHEME>` | `[lint.groups] scheme`, else `floor-trade-block` | `floor-trade-block` or `function-floor`, for a project that has no scheme yet. Refused when it contradicts `bussard.toml`. |
| `--json` | off | Emit `room`, `scheme`, `file`, `added`, `lint_config_written`, `validation` instead of the list. |

| Scheme | main | middle | sub |
|---|---|---|---|
| `floor-trade-block` | floor | trade | block start + role offset |
| `function-floor` | trade | floor | block start + role offset |

Behaviour:

- Running it again for a room and function that already have their block adds nothing. Existing addresses are never renumbered or renamed.
- The scheme is `[lint.groups] scheme` in `bussard.toml`. The first reservation in a project without one writes a `[lint]` table with the scheme, so later reservations and `bussard validate` follow the same convention.
- There is no plan file. For several rooms, run the command once per room, or have an assistant call `knx_scaffold_groups` with the room list.
- A group address that a device file uses but `groups.toml` does not define is declared by `import`, `apply` and the MCP edit tools, named `<channel name or device name> <object function or key>` with the object's DPT, and reported: `added 0/1/3 "Fenster Süd Langzeitbetrieb" (DPT 1.008) to groups.toml, first used by 1.1.47 object 144`. `bussard validate` alone only warns (E001).

## `bussard export-groups`

Write the group-address plan in a format ETS's *Group Addresses -> Import* accepts.

```console
$ bussard export-groups --format ets-csv --out groups.csv
```

| Flag | Default | Meaning |
|---|---|---|
| `--format <FORMAT>` | required | `ets-csv` or `ets-xml`. |
| `--out <FILE>` | required | The file to write. |

Behaviour:

- Names, descriptions and DPTs cross over.
- ETS has no field for the `protected` flag, so it is carried into the description as a leading `[protected]` marker.

??? note "Details: the two formats"
    `ets-csv` is the three-level CSV ETS itself exports: UTF-8 with a BOM, semicolon separated, CRLF line endings, every field quoted, with the columns `Main`, `Middle`, `Sub`, `Address`, `Central`, `Unfiltered`, `Description`, `DatapointType`, `Security`. Main groups, middle groups and addresses each get their own row, and the DPT is in ETS notation (`DPST-1-1`, or `DPT-1` when the model has no sub number).

    `ets-xml` is the `GroupAddress-Export` document in the namespace `http://knx.org/xml/ga-export/01`: nested `GroupRange` elements carrying `Name`, `RangeStart` and `RangeEnd`, with `GroupAddress` leaves carrying `Name`, `Address`, `Description`, `DPTs` and `Security`.

## `bussard doc`

Render the handover documentation folder the KNX guidelines prescribe, from the model and the product models in `.bussard/models/`. Offline; never touches the bus.

```console
$ bussard doc [--out <DIR>] [--format md|html]
```

| Flag | Default | Meaning |
|---|---|---|
| `--out <DIR>` | `docs/installation` | Where to write the files. Files with the same names are overwritten; others are left alone. |
| `--format <FORMAT>` | `md` | `md` (Markdown) or `html` (one self-contained page per file, inline styles, no scripts). |
| `--json` | off | Print the structured document model to stdout instead of writing files. |

| File | Contents |
|---|---|
| `index.md` | Links to everything below, one entry per room sheet. |
| `devices.md` | Individual address, name, location, manufacturer, order number, application, mask, Secure status. |
| `groups.md` | Address, name, DPT, description, protected flag, senders and listeners (device and com-object names). |
| `rooms/<floor>-<room>.md` | Every device in the room with its channels, and one plain line per com object: `Rocker 1 switches Kitchen ceiling light (1/0/10); status from 1/0/12.` Unnamed items fall back to their addresses. A device without a `location:` gets no room sheet. |
| `connection.md` | Transport and gateway or multicast endpoint from `bussard.toml`. Never credentials. |
| `changelog.md` | The last 50 commits touching the model directory, from `git log`. Empty when the directory is not a git repository or `git` is missing. |

Behaviour:

- The output is deterministic: two runs on the same model write identical bytes, with no timestamps, so you can commit the folder and review its diff after every change.

## Related

- [Global options](../global-options.md): options, consent flags and exit codes shared by every command.
- [Model directory](../model-directory.md): the files these commands write, and the bundle format.
- [Diagnostics](../diagnostics.md): every code `validate` reports.
- [Exchange with ETS](../../how-to/exchange-with-ets.md): names into ETS and what a new export changes.
