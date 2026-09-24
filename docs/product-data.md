# Product data (`.knxprod`) and generated models

`bussard` reads vendor product data to learn a device's com-object table, parameters,
and how to download a configuration into it. This document covers the `.knxprod` format,
what `bussard import-product` does with it, the model files it generates, and the
licensing and versioning caveats. The command's flags are in
[reference.md](reference.md#bussard-import-product-file); a worked adopt-a-device recipe
is in [howto.md](howto.md#-add-a-brand-new-device).

## Where product data comes from

A `.knxprod` is a manufacturer's product database for one or more devices. You obtain it
from:

- the manufacturer's service/download site (most publish `.knxprod` files free),
- the MyKNX catalogue (knx.org), or
- an ETS export of a product you already have.

bussard reads these files; it never ships or redistributes them. See
[the never-redistribute rule](#the-never-redistribute-rule) below.

To save you hunting for the right file, bussard ships a
[pointer index](#the-product-data-pointer-index) that maps an order number to where its
`.knxprod` can be downloaded: the URL and a checksum, never the file itself.
`bussard import-product --order-number <ORDER>` uses it to fetch and verify the file for
a device you saw on the bus.

### The ETS project export as product source

An ETS 6 project export (`.knxproj`) carries the converted ApplicationProgram XML of
every product used in the project, unencrypted under `M-<manufacturer>/`. This is the
only route for devices whose vendor ships product data solely as ETS3-era `.vd4`
files, and it is convenient whenever the project already holds the exact application
version a device runs. `bussard import-product <project>.knxproj` (project password
from `BUSSARD_PROJECT_PASSWORD`) generates the product models from that XML, and
`bussard flash <ia> --product <project>.knxproj --application <application-id>`
reads it directly; `--application` is required because a project holds several
application programs. The generated models are byte-for-byte the same as from the
vendor `.knxprod` when the versions match: two ETS3-era Jung devices were flashed from
their project export and verified against ETS captures (issue #135).

A project export is not cached under `vendor/`: it is the owner's project, not vendor
product data, and it is large. Keep it where it is and pass its path.

## What is inside a `.knxprod`

A `.knxprod` is a plain ZIP (no encryption, unlike a password-protected `.knxproj`). It
contains:

```
knx_master.xml            # global enums: manufacturers, mask versions, DPTs
M-XXXX/                    # one folder per manufacturer id, e.g. M-0004 (Jung)
  Hardware.xml            # order numbers → Hardware2Program → application refs
  Catalog.xml             # catalogue tree (not used by bussard)
  M-XXXX_A-….xml          # one ApplicationProgram per programmable variant
  *.signature             # RSA signatures, ignored (see below)
```

The signature files authenticate the archive to ETS. They are not access control: they
stop third parties from forging files ETS will accept, but they do not stop reading a
legitimately downloaded file. bussard skips them.

### The ApplicationProgram XML

Each `M-XXXX_A-….xml` is the interesting part. These files are large (20-28 MB is
normal), so bussard streams them with `quick-xml` and never builds a DOM. It extracts:

- Identity: `Id`, `ApplicationNumber`, `ApplicationVersion`, `MaskVersion`, `Name`
  (resolved to `en-US` where a translation exists), `LoadProcedureStyle`, and the XML
  schema version.
- Com-objects: the `ComObject` base table and `ComObjectRef` overrides, resolved into
  effective number / DPT / flags / size / text, exactly as the `.knxproj` importer does
  (the two agree).
- Parameter types: `TypeNumber` (int min/max/size), `TypeRestriction` (enum value/text
  pairs), `TypeText` (string length), `TypeFloat`, `TypeNone`, and any other `Type*`
  element preserved by name.
- Parameters and parameter refs: name, text, type ref, default value, access, and the
  memory location (`CodeSegment` + `Offset` + `BitOffset`). A parameter-ref
  `Value`/`Access` overrides the parameter's own.
- Code segments: `RelativeSegment` / `AbsoluteSegment` metadata only (id, size,
  address/offset, load-state-machine). The binary payload is dropped.
- Load procedure: the `LdCtrl*` control script (`LdCtrlConnect`, `LdCtrlUnload`,
  `LdCtrlLoad`, `LdCtrlWriteRelMem`, `LdCtrlTaskSegment`, `LdCtrlLoadCompleted`,
  `LdCtrlRestart`, ...), parsed into a typed op list. Unknown ops are kept verbatim so
  nothing is lost. The downloader (`bussard-download`) interprets this list for
  `bussard flash`.

## What `import-product` writes

In positional mode (`bussard import-product <file.knxprod>`) the command:

1. reads the `.knxprod`,
2. caches the source file byte-identically under `<dir>/vendor/<original-name>`
   (skipping the copy, with a note, if an identical file is already there),
3. writes one model file per ApplicationProgram to
   `<dir>/models/<application-id>.yaml`, and
4. creates `<dir>/vendor/.gitignore` (`*`) if `vendor/` did not already exist, so the
   copyrighted originals cannot be committed by accident.

The application id already carries the manufacturer id (`M-0004_A-…`), so the model
filename is just `<application-id>.yaml`, with no redundant prefix.

Output is deterministic: running the command twice on the same file produces
byte-identical model YAML.

## Product data and the device files

The texts that make a device file readable come from the product data, not from the ETS
project: the channel names, the parameter texts and enum labels, and the object
functions. `import` and `adopt` derive the keys from them and record the mapping in
`bussard.lock`, so a channel reads `betriebsart = "Jalousie"` and
`langzeitbetrieb.listen = ["0/1/3"]`. Without the product model, a device file still
holds the device's name, location and links, but its channels are keyed by vendor ids
and its objects by number, and its parameters can be neither checked nor flashed. The
lock carries what the rest of bussard needs (the com-object table, DPTs, flags, module
offsets), so a checkout without `models/` still validates, plans and decodes. See
[the model format](model-format.md#without-product-data).

## The product-data pointer index

Finding the right `.knxprod` for a device you just scanned means knowing its order
number and then hunting the manufacturer's site. The pointer index does that lookup for
you. It is a small JSON file, `data/product-index.json`, that ships with bussard and
holds pointers only: a download URL and a checksum for each product database, never the
copyrighted payload. `import-product --list` shows the index; `--order-number` looks a
number up.

With `--order-number`, bussard:

1. normalizes the order number (trims whitespace, upper-cases) and looks it up in the
   index,
2. shows you what it found and where it will download from,
3. asks for confirmation (a TTY prompt, or `--yes-download` to skip it; on a non-TTY it
   refuses unless `--yes-download` is given),
4. downloads to memory with a hard 100 MiB cap,
5. verifies the download's byte size and SHA-256 against the index, where a mismatch is
   a hard error, since it means the file is not the one the index vouches for (the
   vendor may have re-published it), and
6. caches the verified file under `<dir>/vendor/` and runs the normal import on it.

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
separators: `AKK-0216.03` and `akk-0216.03` match, but `AKK021603` does not, because `-`
and `.` distinguish real KNX order numbers.

### What is in the index

The index seeds a flashability corpus: ~26 bare `.knxprod` databases across five
manufacturers and a range of device types, each verified by downloading it and
computing the checksum. It exists both to help you fetch a device you scanned and to
back the repeatable flashability sweep in `tests-support/product-corpus/` (see
[the corpus findings in DESIGN.md](DESIGN.md#the-flashability-corpus-and-sweep-findings)).

Coverage by manufacturer:

- **MDT** (`M-0083`): switch actuators (AKK, AKS/AKI), blind/shutter (JAL), dimming /
  LED controller (AKD), heating (AKH), binary input (BE), glass push button (BE-GT),
  weather station (SCN-WS), DALI gateway (SCN-DA64x), presence detector (SCN-x360). All
  bare `.knxprod` files hosted directly at mdt.de.
- **Zennio** (`M-0071`): push button (Flat 1), switch/multifunction actuators (MAXinBOX,
  ALLinBOX), dimmer (DIMinBOX), binary input (BIN 44), fan-coil thermostat, presence
  sensor (EyeZen), RGB LED controller (Lumento), A/C gateway (KLIC-DI). Hosted on
  Zennio's CDN (`assets.zennio.com/application_program/`).
- **Lingg & Janke** (`M-00E1`): switch, blind, binary-input and push-button KNX Secure
  devices (mask `0021`). Hosted on the vendor's own domain; the URL path contains a
  literal `&`, which the fetcher passes through verbatim.
- **Theben** (`M-0048`) and **Elsner** (`M-00C9`): heating/dimming actuators and a
  temperature/humidity sensor, hosted on `siblik.com` (an official distributor mirror
  with stable static paths, since theben.de and elsner-elektronik.de themselves ship
  only zips or gate downloads behind a shop/catalogue).

Mixed masks are deliberate. One MDT switch-actuator `.knxprod` commonly bundles a 07B0
(System B) app alongside several 0705 (System 7) ones, and the corpus spans 07B0, 0705,
0701, 0021, 0020 and 0012 families on purpose so the flashability sweep shows real
family coverage: only the 07B0 apps produce an executable flash plan today.

The fetch path deliberately handles only bare `.knxprod` files: the index points at
direct `.knxprod` downloads, and the fetched bytes are imported as-is. This keeps the
download path simple and the checksum meaningful (it covers the exact file ETS would
read).

### Testing against the corpus

The index also backs a repeatable flashability check and a wider one-off 220-file sweep
(384 application programs, 0 parse failures; only System B apps produce an executable
flash plan today, since System 7 and older masks are parsed but not yet flashable). The
corpus mechanics, sweep findings, and per-op refusal analysis are maintainer material:
see [the corpus findings in DESIGN.md](DESIGN.md#the-flashability-corpus-and-sweep-findings).

## The model file format

A model file describes one application program. It is machine-generated and carries a
banner saying so; do not hand-edit it (it is regenerated on re-import). Product models
stay YAML: they are generated, local-only files that nobody edits, so the reasons that
moved the user's model files to TOML do not apply to them. Example (abridged):

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
- `order_numbers`: the catalogue part numbers that map to this program (via
  `Hardware.xml`). This is the join key: a device's `product` (the order number in its
  device file) and its `application` (pinned in `bussard.lock`) both point here.
- `com_objects`: keyed by com-object number, in the same field style as the `objects`
  of `bussard.lock`. `dpt` and `flags` (compact `CRWTUI` string) are the effective, ref-resolved
  values. `size` appears only when there is no DPT to imply it. `ref_id` is the
  application ref the value was resolved through.
- `parameters`: each with its resolved `type`, `default`, and `memory` location. The
  `type` is a tagged union: `!int {min, max, size, signed}`,
  `!enum {values: [{value, text}]}`, `!text {size}`, `!float {encoding, min, max}`,
  `!none`, or `!other {kind, size}`. `memory` (`segment` + `offset` + `bit_offset`) is
  what the parameter phase needs to place the value into the device's parameter memory.
- `load_procedure`: the ordered op summary, a faithful view of the download script.
  `bussard flash` executes the supported subset
  ([reference.md](reference.md#bussard-flash---product-file-address)).

## The never-redistribute rule

Both `<dir>/vendor/` and `<dir>/models/` are local-only and git-ignored:

- `vendor/` holds the copyrighted vendor `.knxprod` verbatim.
- `models/` holds files derived from that copyrighted data.

A user's committed repo carries only their own choices (group addresses, links, device
parameter values), never product data. Anyone who clones the repo regenerates their
models from `.knxprod` files they download themselves. This is the same footing as any
interoperability tool: bussard reads legitimately obtained vendor files to interoperate;
it never hosts or ships them.

## ETS version and namespace caveats

ApplicationProgram XML declares its schema as the default namespace on the root `<KNX>`
element, e.g. `http://knx.org/xml/project/23` for the ETS 6 generation. bussard parses
namespace-agnostically by local element name, so a file from `/20`, `/21`, or `/23`
reads the same way, and it records the schema version in `identity.schema_version` for
provenance.

Other caveats:

- Mask version drives behaviour. `mask_version` (e.g. `07B0`, `0705`, `0701`, `0021`)
  tells the downloader whether the device is property-based (System B) or memory-based
  (older System 1/2). The reader only records it.
- Modules. Complex devices define com-objects and parameters inside reusable module
  definitions (`MD-…`) that the device instantiates (`MD-…_M-n_MI-n_…`). The model file
  lists the application-level refs; bussard maps a device's instances onto them by
  dropping the `_M-n_MI-n` instance segment, with the instance base offsets recorded in
  `bussard.lock`.
- Translations. Names and texts resolve to `en-US` when a translation is present,
  falling back to the file's default language otherwise, matching ETS.
