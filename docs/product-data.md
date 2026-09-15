# Product data (`.knxprod`) and generated models

`bussard` reads vendor product data to learn a device's com-object table, parameters,
and, later, how to download a configuration into it. This document covers the `.knxprod`
format, the `bussard import-product` command, the model files it generates, and the
licensing and versioning caveats.

## Where product data comes from

A `.knxprod` is a manufacturer's product database for one or more devices. You
obtain it from:

- the manufacturer's service/download site (most publish `.knxprod` files free),
- the MyKNX catalogue (knx.org), or
- an ETS export of a product you already have.

bussard reads these files; it never ships or redistributes them. See
[the never-redistribute rule](#the-never-redistribute-rule) below.

To save you hunting for the right file, bussard ships a
[pointer index](#the-product-data-pointer-index) that maps an order number to
where its `.knxprod` can be downloaded — the URL and a checksum, never the file
itself. `bussard import-product --order-number <ORDER>` uses it to fetch and
verify the file for a device you saw on the bus.

## What is inside a `.knxprod`

A `.knxprod` is a plain ZIP (no encryption, unlike a password-protected
`.knxproj`). It contains:

```
knx_master.xml            # global enums: manufacturers, mask versions, DPTs
M-XXXX/                    # one folder per manufacturer id, e.g. M-0004 (Jung)
  Hardware.xml            # order numbers → Hardware2Program → application refs
  Catalog.xml             # catalogue tree (not used by bussard)
  M-XXXX_A-….xml          # one ApplicationProgram per programmable variant
  *.signature             # RSA signatures, ignored (see below)
```

The signature files authenticate the archive to ETS. They are not access
control: they stop third parties from forging files ETS will accept, but they do
not stop reading a legitimately downloaded file. bussard skips them.

### The ApplicationProgram XML

Each `M-XXXX_A-….xml` is the interesting part. These files are large (20–28 MB
is normal), so bussard streams them with `quick-xml` and never builds a DOM.
It extracts:

- Identity: `Id`, `ApplicationNumber`, `ApplicationVersion`, `MaskVersion`,
  `Name` (resolved to `en-US` where a translation exists),
  `LoadProcedureStyle`, and the XML schema version.
- Com-objects: the `ComObject` base table and `ComObjectRef` overrides,
  resolved into effective number / DPT / flags / size / text, exactly as the
  `.knxproj` importer does (the two agree).
- Parameter types: `TypeNumber` (int min/max/size), `TypeRestriction`
  (enum value/text pairs), `TypeText` (string length), `TypeFloat`, `TypeNone`,
  and any other `Type*` element preserved by name.
- Parameters and parameter refs: name, text, type ref, default value,
  access, and the memory location (`CodeSegment` + `Offset` + `BitOffset`). A
  parameter-ref `Value`/`Access` overrides the parameter's own.
- Code segments: `RelativeSegment` / `AbsoluteSegment` metadata only
  (id, size, address/offset, load-state-machine). The binary payload is dropped.
- Load procedure: the `LdCtrl*` control script (`LdCtrlConnect`,
  `LdCtrlUnload`, `LdCtrlLoad`, `LdCtrlWriteRelMem`, `LdCtrlTaskSegment`,
  `LdCtrlLoadCompleted`, `LdCtrlRestart`, …), parsed into a typed op list.
  Unknown ops are kept verbatim so nothing is lost. bussard does not yet
  interpret this; that is the downloader phase (`bussard-download`).

## `bussard import-product`

```
bussard import-product <file.knxprod> [--dir knx]
```

The command:

1. reads the `.knxprod`,
2. caches the source file byte-identically under `<dir>/vendor/<original-name>`
   (skipping the copy, with a note, if an identical file is already there),
3. writes one model file per ApplicationProgram to
   `<dir>/models/<application-id>.yaml`, and
4. creates `<dir>/vendor/.gitignore` (`*`) if `vendor/` did not already exist,
   so the copyrighted originals cannot be committed by accident.

The application id already carries the manufacturer id (`M-0004_A-…`), so the
model filename is just `<application-id>.yaml`, with no redundant prefix.

Output is deterministic: running the command twice on the same file produces
byte-identical model YAML.

## The product-data pointer index

Finding the right `.knxprod` for a device you just scanned means knowing its
order number and then hunting the manufacturer's site. The pointer index does
that lookup for you. It is a small JSON file, `data/product-index.json`, that
ships with bussard and holds *pointers only* — a download URL and a checksum for
each product database, never the copyrighted payload.

```
bussard import-product --list                          # show the index
bussard import-product --order-number "AKK-0216.03"    # look up, confirm, download, import
bussard import-product --order-number "AKK-0216.03" --yes-download   # skip the prompt
```

With `--order-number`, bussard:

1. normalizes the order number (trims whitespace, upper-cases) and looks it up
   in the index,
2. shows you what it found and where it will download from,
3. asks for confirmation (a TTY prompt, or `--yes-download` to skip it; on a
   non-TTY it refuses unless `--yes-download` is given),
4. downloads to memory with a hard 100 MiB cap,
5. verifies the download's byte size **and** SHA-256 against the index — a
   mismatch is a hard error, since it means the file is not the one the index
   vouches for (the vendor may have re-published it), and
6. caches the verified file under `<dir>/vendor/` and runs the normal import on
   it.

### Index schema

`data/product-index.json` is `{ "entries": [ … ] }`, each entry:

| field             | type      | meaning |
| ----------------- | --------- | ------- |
| `manufacturer`    | string    | Human-readable name, e.g. `"MDT"`. |
| `manufacturer_id` | string    | KNX id as inside the `.knxprod`, e.g. `"M-0083"`. |
| `order_numbers`   | [string]  | Every order number this download serves, verbatim as in `Hardware.xml` (e.g. `"AKK-0216.03"`). One file often bundles a whole family. |
| `name`            | string    | Product/family display name. |
| `url`             | string    | Vendor-hosted download URL for the `.knxprod`. |
| `sha256`          | string    | Lower-case hex SHA-256 of the download. |
| `size`            | number    | Exact byte size of the download. |
| `filename`        | string    | Original vendor filename; also the cache name under `vendor/`. |
| `application_ref` | string?   | Optional: the application-program ref an order number resolves to (documentation only). |
| `redistributable` | bool      | Whether bussard may mirror the file itself. Always `false` for vendor-hosted copyrighted data. |
| `notes`           | string?   | Optional version / date-verified / caveats. |

Order-number matching is case- and whitespace-insensitive but preserves interior
separators: `AKK-0216.03` and `akk-0216.03` match, but `AKK021603` does not,
because `-` and `.` distinguish real KNX order numbers.

### What is seeded, and the archive question

The seed entries are MDT switch-actuator databases, verified by downloading them
and computing the checksum:

- **MDT AKK family** (`AKK-0216.03`, `AKK-0416.03`, …): a single bare `.knxprod`
  hosted directly at mdt.de.
- **MDT AKS/AKI family** (`AKS-0216.03`, `AKI-0416.04`, …): likewise a single
  bare `.knxprod`.

The fetch path deliberately handles **only bare `.knxprod` files** — the index
points at direct `.knxprod` downloads, and the fetched bytes are imported as-is.
This keeps the download path simple and the checksum meaningful (it covers the
exact file ETS would read).

Two vendor realities shaped that decision:

- **MDT** hosts bare `.knxprod` files directly on each product page. Perfect for
  the index; no archive handling needed.
- **OpenKNX** publishes GitHub releases with *stable* URLs, which would be ideal
  redistributable seeds — but their release `.zip` bundles do **not** contain a
  built `.knxprod`. They ship the raw ETS `data/*.xml` plus a `Build-knxprod.ps1`
  that runs OpenKNXproducer to assemble the `.knxprod` on your machine. So there
  is no bare `.knxprod` to point at, and bussard does not run their build step.
  If OpenKNX later attaches built `.knxprod` assets to releases, they can be
  added as `redistributable: true` entries.

If a future vendor only offers a zip-of-`.knxprod`, the honest options are to
extract-on-fetch (with the inner filename recorded in the entry) or to skip it;
for now every seeded entry is a direct `.knxprod`, so no archive extraction code
exists.

## The model file format

A model file describes one application program. It is machine-generated and
carries a banner saying so; do not hand-edit it (it is regenerated on re-import).
Example (abridged):

```yaml
# Product model (generated by `bussard import-product`).
# … banner …
identity:
  id: M-00FA_A-0001-11-ABCD-O000A
  name: Fixture App
  application_number: 1
  application_version: 17
  mask_version: 07B0
  load_procedure_style: MergedProcedure
  schema_version: '23'
order_numbers:
- TEST-1
com_objects:
  0:
    text: Switch
    function_text: On/Off
    dpt: '1.001'
    flags: CRWT
    ref_id: M-00FA_A-0001-11-ABCD-O000A_O-0_R-1
  1:
    text: Value
    dpt: '9.001'
    flags: CRT
    ref_id: M-00FA_A-0001-11-ABCD-O000A_O-1_R-1
parameters:
- id: M-00FA_A-0001-11-ABCD-O000A_P-1
  name: Threshold
  text: Threshold
  type: !int
    min: 0
    max: 100
    size: 8
  default: '75'
  memory:
    segment: M-00FA_A-0001-11-ABCD-O000A_RS-4
    offset: 3
    bit_offset: 0
load_procedure:
- connect
- unload lsm=1
- load lsm=1
- write_rel_mem obj=5 offset=0 size=10 applies_to=full,par
- load_completed lsm=1
- restart
- disconnect
```

Field notes:

- `identity`: the application program's stable identity.
- `order_numbers`: the catalogue part numbers that map to this program
  (via `Hardware.xml`). This is the join key: a device file's `application_ref`
  and its `order_number` both point here.
- `com_objects`: keyed by com-object number, in the same field style as the
  device schema. `dpt` and `flags` (compact `CRWTUI` string) are the effective,
  ref-resolved values. `size` appears only when there is no DPT to imply it.
  `ref_id` is the application ref the value was resolved through.
- `parameters`: each with its resolved `type`, `default`, and `memory`
  location. The `type` is a tagged union: `!int {min, max, size, signed}`,
  `!enum {values: [{value, text}]}`, `!text {size}`,
  `!float {encoding, min, max}`, `!none`, or `!other {kind, size}`.
  `memory` (`segment` + `offset` + `bit_offset`) is what a later phase needs to
  place the value into the device's parameter memory.
- `load_procedure`: the ordered op summary. This is a faithful, still
  uninterpreted view of the download script; the downloader phase turns it
  into bus traffic.

## The never-redistribute rule

Both `<dir>/vendor/` and `<dir>/models/` are local-only and git-ignored:

- `vendor/` holds the copyrighted vendor `.knxprod` verbatim.
- `models/` holds files derived from that copyrighted data.

A user's committed repo carries only their own choices (group addresses, links,
device parameter values), never product data. Anyone who clones the repo
regenerates their models from `.knxprod` files they download themselves. This is
the same footing as any interoperability tool: bussard reads legitimately
obtained vendor files to interoperate; it never hosts or ships them.

## ETS version and namespace caveats

ApplicationProgram XML declares its schema as the default namespace on the root
`<KNX>` element, e.g. `http://knx.org/xml/project/23` for the ETS 6 generation.
bussard parses namespace-agnostically by local element name, so a file from
`/20`, `/21`, or `/23` reads the same way, and it records the schema version in
`identity.schema_version` for provenance.

Other caveats:

- Mask version drives behaviour. `mask_version` (e.g. `07B0`, `0705`,
  `0701`, `0021`) tells later phases whether the device is property-based
  (System B) or memory-based (older System 1/2). The reader only records it.
- Modules. Complex devices define com-objects and parameters inside
  reusable module definitions (`MD-…`) that the device instantiates
  (`MD-…_M-n_MI-n_…`). The model file lists the application-level refs; the
  device file maps its instances onto them by dropping the `_M-n_MI-n` instance
  segment.
- Translations. Names and texts resolve to `en-US` when a translation is
  present, falling back to the file's default language otherwise, matching ETS.
