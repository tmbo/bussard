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
[below](#the-flashability-corpus)).

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

### The flashability corpus

`tests-support/product-corpus/` turns the index into a repeatable "can bussard flash
this today?" check. `fetch.sh` reads `corpus.txt` (one order number per index entry) and
runs `bussard import-product --order-number … --yes-download` for each, downloading and
checksum-verifying every file into a git-ignored `cache/`. The env-gated test
`crates/bussard-download/tests/flash_corpus.rs` then dry-runs `plan_flash` over every
application program in the cache and reports which lower to an executable plan, which are
refused, and — for the refused System B apps — which load-procedure op blocked them. With
`BUSSARD_PRODUCT_CORPUS` unset the test skips green, so CI never downloads vendor data.
See `tests-support/product-corpus/README.md` for the clean-machine repro.

Two vendor realities shaped that decision:

- MDT hosts bare `.knxprod` files directly on each product page. Perfect for the index;
  no archive handling needed.
- OpenKNX publishes GitHub releases with stable URLs, which would be ideal
  redistributable seeds, but their release `.zip` bundles do not contain a built
  `.knxprod`. They ship the raw ETS `data/*.xml` plus a `Build-knxprod.ps1` that runs
  OpenKNXproducer to assemble the `.knxprod` on your machine. So there is no bare
  `.knxprod` to point at, and bussard does not run their build step. If OpenKNX later
  attaches built `.knxprod` assets to releases, they can be added as
  `redistributable: true` entries.

If a future vendor only offers a zip-of-`.knxprod`, the honest options are to
extract-on-fetch (with the inner filename recorded in the entry) or to skip it; for now
every seeded entry is a direct `.knxprod`, so no archive extraction code exists.

### The broad sweep (220-file corpus)

The committed index stays small and curated, but a wider one-off sweep read a much
larger corpus through the same library code to map what the product-data pipeline and
flash engine handle today. It pulled **220 `.knxprod` files across 8 manufacturers**
(MDT, Zennio, Theben, Elsner, Lingg & Janke, plus three vendors not previously covered:
Steinel, EAE Technology, Arcus-EDS) and ran `read_knxprod` + a dry-run `plan_flash` on
every application program at its own mask. The full pointer list (URL, SHA-256, size,
vendor) lives in `tests-support/product-corpus/sweep-manifest.json`; like the index it
holds pointers only, never vendor bytes. The sweep script may unzip a zip-of-`.knxprod`
locally (that is how the Arcus-EDS gateways and a few Zennio panels were read), which the
committed index deliberately still does not do.

Headline numbers: **384 application programs, 83 executable, 4 refused, 0 parse failures.**
`read_knxprod` parsed every one of the 220 files without error, over schema versions
`/11`, `/13`, `/14`, `/20`, `/21`, `/23` and 13 distinct mask families (the seed corpus
had 6): the sweep added `0011`/`0012`/`0020` (BCU1/BCU2), `0025`, and the KNX-RF and
coupler families `0912`, `091A`, `2705`, `27B0`, `2920`. Only the 82 System B (`07B0`)
apps are flash candidates, and 78 of those lower to an executable plan.

**What blocks a flash today.** Only four System B apps refused, for two distinct reasons:

- **`LdCtrlCompareRelMem` (2 apps)** — a masked, inverted relative-memory verify op the
  parser keeps as `LoadOp::Raw` and the planner refuses. Real shape (MDT BE-GTSx6Tx, MDT
  JTA blind push button): `<LdCtrlCompareRelMem InlineData="FF" Mask="FF" Invert="true"
  ObjIdx=… Offset=… Size=…>`. This is the top roadmap op: it is a read-and-compare, so it
  is executable once typed, and it sits inside otherwise-complete procedures.
- **Enum default not a declared member (2 apps)** — the Zennio Z40 and Z70 v2 panels
  declare a parameter whose own default `Value` is not one of its enumeration's members,
  so `compute_parameter_image` refuses the whole download (`UnresolvableImage`). The
  strict membership check has real user cost here: it blocks two otherwise fully
  executable panels over a vendor data-quality quirk.

**Other unhandled load ops** the sweep surfaced (all kept as `LoadOp::Raw`, none yet
blocking an executable procedure but present in the wild): `LdCtrlTaskCtrl2`,
`LdCtrlTaskPtr`, `LdCtrlDeclarePropDesc`, `LdCtrlDelay`, `LdCtrlCompareMem`. Load-op use
splits cleanly by mask family: System B (`07B0`) procedures are property-and-MCB based
(`LdCtrlRelSegment`, `WriteRelMem`, `LoadImageProp`, `CompareProp`), while System 7/2
(`0705`/`0701`/`0021`) procedures are segment based (`AbsSegment`, `WriteMem`), and the
RF/coupler masks are where the `TaskCtrl2`/`TaskPtr`/`DeclarePropDesc` ops appear.

**Parameter-type coverage.** The four encodable shapes dominate (Int, Enum, Text, Float).
Six type elements fall through to `ParameterType::Other` and are preserved by name but not
encoded beyond a byte-multiple fallback: `TypeColor` (RGB colour), `TypeTime`,
`TypeIPAddress`, `TypePicture` (icon references), `TypeRawData` (raw blobs, up to ~150 KB
in Zennio panels), and stray `TypeRestriction`. None is silently dropped.

Each new construct has a fabricated regression fixture (fake data reproducing the
structural shape, never vendor content) under `crates/bussard-ets/tests/fixtures/`
(the `LdCtrl*` ops and the `Other` parameter types) and
`crates/bussard-prod/tests/fixtures/` (the enum-default-not-a-member image blocker); see
those directories' `README.md` for the intended test per fixture. The sweep is a
point-in-time study, not a CI job: it is not re-run automatically, and the committed
flashability corpus (`corpus.txt` + `flash_corpus.rs`) remains the ongoing check.

## The model file format

A model file describes one application program. It is machine-generated and carries a
banner saying so; do not hand-edit it (it is regenerated on re-import). Example
(abridged):

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
  `Hardware.xml`). This is the join key: a device file's `application_ref` and its
  `order_number` both point here.
- `com_objects`: keyed by com-object number, in the same field style as the device
  schema. `dpt` and `flags` (compact `CRWTUI` string) are the effective, ref-resolved
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
  lists the application-level refs; the device file maps its instances onto them by
  dropping the `_M-n_MI-n` instance segment.
- Translations. Names and texts resolve to `en-US` when a translation is present,
  falling back to the file's default language otherwise, matching ETS.
