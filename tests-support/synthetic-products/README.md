# Synthetic products

Small fabricated KNX products under manufacturer `M-00FA` (the KNX test
manufacturer), one construct per product, for checking bussard, knx-sim and
ETS against each other without vendor data (epic #596). Each product is a
TOML spec; `generate.py` renders it into the product XML, which is committed
next to it, and zips it on demand.

```
<name>/product.toml                   the spec (edit this)
<name>/xml/M-00FA/Catalog.xml         rendered, committed
<name>/xml/M-00FA/Hardware.xml        rendered, committed
<name>/xml/M-00FA/M-00FA_A-<nnnn>-<vv>-0000.xml   rendered, committed
<name>/build/<name>.knxprod           zipped by --zip, gitignored
<name>/build/<name>-signed.knxprod    signed in the VM, gitignored
<name>/signed.toml                    the signed application id (generate.py --signed-id)
```

## Catalogue

<!-- catalogue:begin (generate.py --catalogue) -->
| product | order number | mask | construct | issues |
| --- | --- | --- | --- | --- |
| [`syn-choose-never-shown`](syn-choose-never-shown/product.toml) | `NEST-GHOST` | 07B0 | choose on a never-shown memoryless parameter, default branch only | #474, #563 |
| [`syn-choose-partial-segment`](syn-choose-partial-segment/product.toml) | `NEST-HALF` | 07B0 | load-procedure choose writing half the segment | #411 |
| [`syn-choose-per-ref`](syn-choose-per-ref/product.toml) | `NEST-TWIN` | 07B0 | choose on the unreached second ParameterRef of a reached parameter | #563 |
| [`syn-dynamic-tests`](syn-dynamic-tests/product.toml) | `NEST-WORM` | 07B0 | Channel and ParameterBlock with choose on single, list, comparison and default tests | #345 |
| [`syn-hidden-default`](syn-hidden-default/product.toml) | `NEST-EGGHEAT` | 07B0 | hidden parameter, default differs from template | #448 |
| [`syn-le-order`](syn-le-order/product.toml) | `NEST-ALTI` | 07B0 | ParameterByteOrder LittleEndian with integers and floats | #403 |
| [`syn-legacy-patch-always`](syn-legacy-patch-always/product.toml) | `NEST-PATCH` | 07B0 | hidden LegacyPatchAlways parameter, default differs from template | #450 |
| [`syn-master-reset`](syn-master-reset/product.toml) | `NEST-RESET` | 07B0 | Master Reset erase code 1 in the load procedure | #546, #611 |
| [`syn-master-reset-code4`](syn-master-reset-code4/product.toml) | `NEST-RESET4` | 07B0 | Master Reset erase code 4 after the segment allocation | #546, #600, #611 |
| [`syn-minimal`](syn-minimal/product.toml) | `NEST-LIGHT` | 07B0 | baseline | #596 |
| [`syn-param-calculation`](syn-param-calculation/product.toml) | `NEST-CALC` | 07B0 | JavaScript ParameterCalculation, one output LegacyPatchAlways | #427, #450 |
| [`syn-relseg-fill`](syn-relseg-fill/product.toml) | `NEST-FILL` | 07B0 | RelSegment Mode 0 with Fill 255 | #480 |
| [`syn-s7-0701`](syn-s7-0701/product.toml) | `NEST-BKDOOR` | 0701 | System 7 baseline (0701, memory-mapped LSM) | #596, #488, #481 |
| [`syn-s7-0705`](syn-s7-0705/product.toml) | `NEST-DOOR` | 0705 | System 7 baseline (0705, property LSM) | #596, #488, #479, #588, #487 |
| [`syn-s7-choose-split`](syn-s7-choose-split/product.toml) | `NEST-SPLIT` | 0705 | load-procedure choose splitting the parameter AbsSegment | #411, #413 |
| [`syn-s7-hidden-default`](syn-s7-hidden-default/product.toml) | `NEST-EGGBAK` | 0705 | hidden parameter on System 7, default differs from template | #448 |
| [`syn-s7-hidden-default-p11`](syn-s7-hidden-default-p11/product.toml) | `NEST-EGGOLD` | 0705 | hidden parameter on System 7 in schema project/11 | #448 |
| [`syn-s7-lsm5`](syn-s7-lsm5/product.toml) | `NEST-TWIG5` | 0701 | TaskSegment on LsmIdx 5 (0701) | #489 |
| [`syn-s7-pei80`](syn-s7-pei80/product.toml) | `NEST-CLAW` | 0701 | PeiType 128 on 0701 | #483 |
| [`syn-s7-taskptr`](syn-s7-taskptr/product.toml) | `NEST-HUNT` | 0705 | TaskPtr and TaskCtrl2 records on LSM 3 | #527 |
| [`syn-text-undeclared`](syn-text-undeclared/product.toml) | `NEST-SQUAWK` | 07B0 | TypeText non-ASCII default, no TextParameterEncoding | #416 |
| [`syn-union-default-range`](syn-union-default-range/product.toml) | `NEST-STRAY` | 07B0 | hidden union member, default outside its type | #405 |
<!-- catalogue:end -->

## Theme

`bussard` is German for buzzard, so the synthetic products are the appliances
of a buzzard's nest. Each product is a real appliance in that home: an egg
heater, a worm-movement detector, a twig-door actuator.

- The appliance hints at the construct where it can: a two-byte little-endian
  product could be a tree-altitude meter (Höhenmesser).
- Order numbers are ASCII, no spaces, at most 12 characters, prefixed `NEST-`.
- The catalogue section stays `M-00FA_CS-27`, titled "The buzzard's nest".
- German `translations` of the names are welcome and short.
- The theme lives in `[product] text`, `order_number`, `hardware_name` and
  `[application] name`; directory names and `construct` never change for it.

## Commands

```sh
uv run tests-support/synthetic-products/generate.py                # render every product's xml/
uv run tests-support/synthetic-products/test_generate.py           # unit tests of the rendering paths
uv run tests-support/synthetic-products/generate.py --check        # exit 1 if xml/ or signed.toml is stale
uv run tests-support/synthetic-products/generate.py --zip syn-minimal
uv run tests-support/synthetic-products/generate.py --catalogue    # rewrite the table above
uv run tests-support/synthetic-products/generate.py syn-minimal \
    --signed-id tests-support/synthetic-products/syn-minimal/build/syn-minimal-signed.knxprod
```

`generate.py` is stdlib-only Python 3.11. A render is byte-identical on every
run (attributes in a fixed order, two-space indent, LF, no BOM); the zip has
fixed timestamps and a fixed entry order.

## The spec

One `product.toml` per directory. Tables and keys:

| table | keys | rendered as |
| --- | --- | --- |
| `[doc]` | `purpose` (one paragraph), `construct` (a few words), `issues` (numbers) | the catalogue row; not in the XML |
| `[product]` | `text`, `order_number`, `hardware_name`, `hardware_serial` (`00FA` + 8 hex digits), `bus_current` (mA); optional `hardware_version` (1), `rail_mounted` (false) | `Hardware`, `Product`, `Hardware2Program`, `CatalogItem` |
| `[application]` | `number` (0x2700 to 0x2AFF: 0x27xx System B, 0x28xx System 7, 0x29xx Secure, 0x2Axx RF and IP), `version` (one octet), `name`, `mask` (`07B0`, or `0705`/`0701` for System 7), `load_procedure_style` (`MergedProcedure` on 07B0, `ProductProcedure` on System 7), `address_table_max_entries`, `association_table_max_entries`; optional `translations` (`{ "de-DE" = "..." }` for the name); optional `schema` (`23`, or `11`: namespace `http://knx.org/xml/project/11` and `MinEtsVersion="4.0"` in all three files, the shape of the #448 vendor applications; `sign.py` then uses ETS's project-11 master data); System 7 only: `address_table_segment`, `association_table_segment`, `com_object_table_segment` (the absolute segment each table starts in, offset 0; required) and `pei_type` (0) | `ApplicationProgram`, `AddressTable`, `AssociationTable`, `Languages` |
| `[application.options]` | any `Options` attribute of the KNX schema, e.g. `SupportsExtendedMemoryServices = true`, `ParameterByteOrder = "LittleEndian"` | `Options` |
| `[[segment]]` | `name`, `kind` (`relative`), `lsm`, `size`; optional `fill` (the initial octet, 0) | `RelativeSegment` with its `Data` |
| `[[parameter_type]]` | `name`, `kind`; `enum`: `size_bits`, `values = [{ value, text }]`; `number`: `size_bits`, `signed`, `min`, `max`; `float`: `encoding` (`DPT 9`, `IEEE-754 Single`, `IEEE-754 Double`; 16, 32, 64 bits), `min`, `max`; `text`: `size_octets` | `TypeRestriction`, `TypeNumber`, `TypeFloat`, `TypeText` |
| `[[parameter]]` | `name`, `type`, `text`, `default`, and either `memory = { segment, offset, bit_offset }`, `union = { name, offset, bit_offset }` (a member at its offset in the union) or `virtual = true` (no memory, it only steers the Dynamic tree; #474); optional `access` (`None`, `Read`, `ReadWrite`) and `legacy_patch_always` (#450) | `Parameter` (`_P-<n>`, a union member `_UP-<n>`), one `ParameterRef` each |
| `[[parameter_ref]]` | `name`, `parameter` | a further `ParameterRef` of the parameter (`_P-<n>_R-<k>`, numbered after every parameter's own ref); blocks and chooses name it like a parameter (#563) |
| `[[union]]` | `name`, `size_bits`, `memory = { segment, offset, bit_offset }`; optional `default` (the member that is `DefaultUnionParameter`) | `Union` with its `Memory`, after the plain parameters |
| `[[parameter_calculation]]` | `name`, `language` (`JavaScript`), `inputs` and `outputs` (`[{ parameter, alias }]`), `lr_script`, `rl_script` | a `ParameterCalculation` (`_PC-<n>`) in the inline form: `RLTransformation`, `LRTransformation`, `LParameters`, `RParameters` with `AliasName`s (#427) |
| `[[com_object]]` | `number`, `name`, `text`, `function_text`, `size` (`"1 Bit"`), `dpt` (`"DPST-1-1"`), `flags` (of `C R W T U I`), `priority` (`Low`, `High`, `Alert`) | `ComObject`, one `ComObjectRef` each |
| `[[dynamic.block]]` | `name`, `text`, `parameters` (names), `com_objects` (numbers) | a `ParameterBlock` in the `ChannelIndependentBlock`; a parameter no block names is never shown (#448) |
| `choose` of a block | `[{ parameter, when = [{ test or default = true, parameters, com_objects }] }]` | a `<choose ParamRefId>` inside the `ParameterBlock` after its refs, each `<when>` holding refs and com objects directly (#345) |
| `[[dynamic.channel]]` | `name`, `text`, `number` (a string), `[[dynamic.channel.block]]` (keys as `[[dynamic.block]]`) | a `<Channel>` (`_CH-<n>`) after the `ChannelIndependentBlock`, its blocks numbered after every other (#345) |
| `[[dynamic.choose]]` | `parameter` (or a `[[parameter_ref]]`), `[[dynamic.choose.when]]` with `test` (as ETS writes it: `"1"`, `"0 2"`, `">=2"`) or `default = true`, and `[[dynamic.choose.when.block]]` (keys as `[[dynamic.block]]`) | a `<choose ParamRefId>` in the `ChannelIndependentBlock` after the blocks, each `<when>` holding its blocks, numbered after them (#474, #563) |
| `[[load_procedure]]` | `merge_id`, `ops = [{ op = "...", ... }]` | `LoadProcedure` |

Load ops: `LdCtrlRelSegment` (`lsm`, `size`, `mode`, `fill`),
`LdCtrlWriteRelMem` (`object`, `offset`, `size`, `verify`) and
`LdCtrlMasterReset` (`erase_code`, `channel`). A System 7 product procedure
also takes `LdCtrlTaskPtr` (`lsm`, `init_ptr`, `save_ptr`, `serial_ptr`) and
`LdCtrlTaskCtrl2` (`lsm`, `callback`, `address`, `seg0`, `seg1`). `{ op = "choose", parameter,
when = [{ test, ops }, { default = true, ops }] }` renders a `<choose
ParamRefId>` with its `<when>` branches inside the procedure (#411).

The schema reaches further than the generator does. These are reserved for
the catalogue products that need them (step 4 of #596), and a spec that uses
one stops with "part of the schema but no product uses it yet": masks other
than 07B0 (System 7 twins), `ProductProcedure`, absolute segments, parameter
type kinds `time`, `ip_address`, `raw`, VBScript calculations and the
`LRTransformationFunc` form with a `<Script>`, explicit com
object refs, and the load
ops `LdCtrlLoadImageProp`, `LdCtrlWriteProp`,
`LdCtrlCompareProp`, `LdCtrlAbsSegment` and the connection and state ops of a
product procedure. An unknown key or op stops with an error naming it.

Ids follow ETS: `M-00FA_A-<number>-<version>-0000` for the application, its
parts prefixed with it (`_RS-04-00000`, `_PT-<name>`, `_P-<n>`, `_P-<n>_R-<n>`,
`_O-<number>`, `_O-<number>_R-<n>`, `_PB-<n>`); hardware
`M-00FA_H-<serial>-<version>`, product `..._P-<order number>` and catalogue
item with ETS's escaping: every octet but a letter or a digit becomes `.XX`,
the `-` too, since it separates the parts of an id (`NEST-LIGHT` becomes
`NEST.2DLIGHT`; unescaped, ETS's catalogue failed after the import). Every
product shares the catalogue section `M-00FA_CS-27` "The buzzard's nest". Application numbers
start at 0x2700 (0x28xx for System 7): KNX Virtual uses 0x25xx and the DA.tp
clone 0x2600. An absolute segment is `_AS-<address, four hex digits>`.

## The id rule

The rendered application id ends in `0000`. ETS expects the last four hex
digits to be a fingerprint of the program's `Hash`, and the signer
(`tools/ets-sweep/synthetic/sign.py`) computes both and renames the id:
`M-00FA_A-2700-10-0000` became `M-00FA_A-2700-10-D80E`. Everything that names
the signed id (the knx-sim config of a capture, the oracle row) is written
after signing; `generate.py <name> --signed-id <id or signed .knxprod>`
records it in `<name>/signed.toml` together with the hash of the XML it was
signed from, and `--check` reports a `signed.toml` whose XML has changed since.

## The master data stub

The zip carries `knx_master.xml` as the stub `<KNX/>`; the real master data is
KNX Association data and is never committed. knx-sim and `bussard
import-product` read a product with the stub. Only ETS needs the real one:
ETS 6.4 refuses the stub on import ("Die Eingabezeichenfolge hat das falsche
Format", a FormatException reading the master data version, 2026-10-30).
`sign.py` therefore replaces a stub with ETS's own
`C:\ProgramData\KNX\XML\project-23\knx_master.xml` in the VM; the signed
file is a build artefact and stays gitignored.

bussard needs no master data: the flash plan of a `MergedProcedure` product
splices the application's `LoadProcedure` blocks into the mask's load
procedure, and when `knx_master.xml` is the stub bussard uses its built-in
template for the mask (07B0, 27B0, 57B0; #607), the same ops as ETS's master
data. `bussard flash` of a product zipped with the stub programs every object
and `bussard plan` after it is a no-op; the oracle row of a signed product,
whose file carries the real master data, compares the same sequence.

## Captures

Each product is downloaded by ETS into knx-sim once; the capture is ours and
is committed under `captures/synthetic/`, where CI replays it (epic #596,
steps 5 and 6). The flow, in the Windows VM of `tools/ets-sweep/README.md`
with no other sweep running:

1. Edit `<name>/product.toml`, run `generate.py` and `generate.py --catalogue`,
   commit the spec, `xml/` and this README.
2. Build the VM's simulator from the commit you capture with
   (`tools/ets-sweep/winbuild-knx-sim.sh`, `uv run tools/ets-sweep/vm.py install`);
   the build writes the commit next to `knx-sim.exe` for the manifest.
3. `uv run tools/ets-sweep/synthetic/capture.py <name>`. It renders and zips
   the product, signs it in the VM (`sign.py`, ETS's master data swapped in),
   records the signed id (`generate.py --signed-id`), imports the signed file
   into ETS's catalogue and finds its order number there, has ETS download it
   at its defaults into knx-sim (`calibrate.py`), copies the capture here,
   runs the oracle row of the committed files and writes the row and the
   manifest entry.
4. Commit `captures/synthetic/` with the product.

```
captures/synthetic/manifest.json                one entry per product and variant
captures/synthetic/rows.txt                     the oracle rows (95-offline-oracle.sh --check)
captures/synthetic/model/bussard.toml           the empty model the rows plan against
captures/synthetic/<name>/defaults/ets.pcapng   the sim's capture of the ETS download
captures/synthetic/<name>/defaults/ops.txt      knxtrace ops of it
captures/synthetic/<name>/defaults/requests.txt the tool's requests (distil.py), for knx-sim's replay
captures/synthetic/<name>/defaults/image.json   the segments and octets ETS wrote (knxtrace image)
captures/synthetic/<name>/defaults/driver.json  the ETS driver's steps and ETS's history pane
captures/synthetic/<name>/defaults/sim.yaml     a loopback knx-sim of the device (needs --zip)
```

The manifest entry holds the ETS version, the commit the simulator was built
from, the digest of the `xml/` the capture was taken with (the `xml_sha256`
of `signed.toml`), the signed id, the date, and the oracle verdict and
coverage. No `.knxprod` and no `knx_master.xml` is committed: the rows name
the product's `xml/` directory, which `95-offline-oracle.sh` zips with the
stub master, and the application is the rendered id, since the signer's
fingerprint never reaches the wire (`PID_PROGRAM_VERSION` carries the
manufacturer, the application number and the version).

CI replays every capture on each push (`dev/testing.md`, "CI"): the rows
run `--check` against `bussard flash --dry-run`, knx-sim replays
`requests.txt` and compares its memory with `image.json`
(`knx-sim/tests/synthetic_calibration.rs`), and the sim loop flashes every
product with seeded configurations.

**A product change requires a re-capture.** A capture of other XML says
nothing about the committed product, so
`crates/bussard-cli/tests/it/synthetic_captures.rs` fails, ungated, when a
product's `xml/` digest differs from its manifest entry, and names the
`capture.py` command. A spec change that does not reach the XML (the `[doc]`
table) needs none.

A product bussard refuses to flash, where the refusal is the finding it
exists for, is listed in `sim-loop-refusals.json` with the open issue and a
phrase of the refusal; the synthetic sim loop accepts that refusal and fails
once the product flashes.

The tests `crates/bussard-prod/tests/it/synthetic_products.rs` and
`knx-sim/tests/synthetic_products.rs` zip every product's `xml/` with the stub
and read it, ungated; they need neither Python nor the VM.
