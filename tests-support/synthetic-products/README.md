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
| [`syn-assign`](syn-assign/product.toml) | `NEST-CHORE` | 07B0 | Assign from a reached parameter onto an unshown placed one | #345 |
| [`syn-choose-never-shown`](syn-choose-never-shown/product.toml) | `NEST-GHOST` | 07B0 | choose on a never-shown memoryless parameter, default branch only | #474, #563 |
| [`syn-choose-partial-segment`](syn-choose-partial-segment/product.toml) | `NEST-HALF` | 07B0 | load-procedure choose writing half the segment | #411 |
| [`syn-choose-per-ref`](syn-choose-per-ref/product.toml) | `NEST-TWIN` | 07B0 | choose on the unreached second ParameterRef of a reached parameter | #563 |
| [`syn-color-param`](syn-color-param/product.toml) | `NEST-COLOUR` | 07B0 | TypeColor RGB parameter in memory | #616 |
| [`syn-color-param-hsv`](syn-color-param-hsv/product.toml) | `NEST-COLHSV` | 07B0 | TypeColor HSV parameter in memory | #616 |
| [`syn-color-param-hsv2`](syn-color-param-hsv2/product.toml) | `NEST-COLHSV2` | 07B0 | TypeColor HSV parameter, non-primary defaults | #616 |
| [`syn-com-objects`](syn-com-objects/product.toml) | `NEST-CHIRP` | 07B0 | one com object per size code, every flag combination, three priorities, ReadOnInit | #541, #545, #540, #686 |
| [`syn-dynamic-tests`](syn-dynamic-tests/product.toml) | `NEST-WORM` | 07B0 | Channel and ParameterBlock with choose on single, list, comparison and default tests | #345 |
| [`syn-hidden-default`](syn-hidden-default/product.toml) | `NEST-EGGHEAT` | 07B0 | hidden parameter, default differs from template | #448 |
| [`syn-ip-57b0`](syn-ip-57b0/product.toml) | `NEST-THERMAL` | 57B0 | System B on KNX IP (mask 57B0, MT-5) | #389 |
| [`syn-ip-address-param`](syn-ip-address-param/product.toml) | `NEST-HOMING` | 07B0 | TypeIPAddress parameter in memory | #457 |
| [`syn-ip-enabled-tp`](syn-ip-enabled-tp/product.toml) | `NEST-UPLINK` | 07B0 | IP-enabled TP hardware, the KNXnet/IP object writes | #455 |
| [`syn-le-order`](syn-le-order/product.toml) | `NEST-ALTI` | 07B0 | ParameterByteOrder LittleEndian with integers and floats | #403 |
| [`syn-legacy-patch-always`](syn-legacy-patch-always/product.toml) | `NEST-PATCH` | 07B0 | hidden LegacyPatchAlways parameter, default differs from template | #450 |
| [`syn-map-error`](syn-map-error/product.toml) | `NEST-FALSE` | 07B0 | LdCtrlMapError around LdCtrlUnload LsmIdx 5 (07B0 ProductProcedure) | #614 |
| [`syn-master-reset`](syn-master-reset/product.toml) | `NEST-RESET` | 07B0 | Master Reset erase code 1 in the load procedure | #546, #611 |
| [`syn-master-reset-code4`](syn-master-reset-code4/product.toml) | `NEST-RESET4` | 07B0 | Master Reset erase code 4 after the segment allocation | #546, #600, #611 |
| [`syn-minimal`](syn-minimal/product.toml) | `NEST-LIGHT` | 07B0 | baseline | #596 |
| [`syn-module-repeat`](syn-module-repeat/product.toml) | `NEST-TRIFEED` | 07B0 | ModuleDef with allocator-fed bases, instantiated three times by a Repeat | #449 |
| [`syn-param-calculation`](syn-param-calculation/product.toml) | `NEST-CALC` | 07B0 | JavaScript ParameterCalculation, one output LegacyPatchAlways | #427, #450 |
| [`syn-product-07b0`](syn-product-07b0/product.toml) | `NEST-PLAN` | 07B0 | ProductProcedure on 07B0 with the tables as RelSegments | #614 |
| [`syn-property-param`](syn-property-param/product.toml) | `NEST-TERR` | 07B0 | parameter placed in a property, written by LdCtrlWriteProp | #669 |
| [`syn-relseg-fill`](syn-relseg-fill/product.toml) | `NEST-FILL` | 07B0 | RelSegment Mode 0 with Fill 255 | #480 |
| [`syn-rf-27b0`](syn-rf-27b0/product.toml) | `NEST-RADIO` | 27B0 | System B on KNX RF (mask 27B0, MT-2) | #604 |
| [`syn-s7-0701`](syn-s7-0701/product.toml) | `NEST-BKDOOR` | 0701 | System 7 baseline (0701, memory-mapped LSM) | #596, #488, #481 |
| [`syn-s7-0705`](syn-s7-0705/product.toml) | `NEST-DOOR` | 0705 | System 7 baseline (0705, property LSM) | #596, #488, #479, #588, #487 |
| [`syn-s7-choose-split`](syn-s7-choose-split/product.toml) | `NEST-SPLIT` | 0705 | load-procedure choose splitting the parameter AbsSegment | #411, #413 |
| [`syn-s7-delay`](syn-s7-delay/product.toml) | `NEST-HATCH` | 0701 | LdCtrlDelay before LdCtrlRestart (0701) | #615 |
| [`syn-s7-hidden-default`](syn-s7-hidden-default/product.toml) | `NEST-EGGBAK` | 0705 | hidden parameter on System 7, default differs from template | #448 |
| [`syn-s7-hidden-default-ets4`](syn-s7-hidden-default-ets4/product.toml) | `NEST-EGGV4` | 0705 | hidden parameter on System 7, project/23 with MinEtsVersion 4.0 | #448 |
| [`syn-s7-hidden-default-p11`](syn-s7-hidden-default-p11/product.toml) | `NEST-EGGOLD` | 0705 | hidden parameter on System 7 in schema project/11 | #448 |
| [`syn-s7-lsm5`](syn-s7-lsm5/product.toml) | `NEST-TWIG5` | 0701 | TaskSegment on LsmIdx 5 (0701) | #489 |
| [`syn-s7-lsm5-0705`](syn-s7-lsm5-0705/product.toml) | `NEST-TWIG5G` | 0705 | TaskSegment on LsmIdx 5 (0705) | #489 |
| [`syn-s7-no-comobjects`](syn-s7-no-comobjects/product.toml) | `NEST-SILENT` | 0701 | com objects only in a block not reached at defaults (0701) | #562, #475 |
| [`syn-s7-pei80`](syn-s7-pei80/product.toml) | `NEST-CLAW` | 0701 | PeiType 128 on 0701 | #483 |
| [`syn-s7-pid204`](syn-s7-pid204/product.toml) | `NEST-PLUME` | 0701 | LdCtrlWriteProp PID 204 with Count 2 on the application object (0701) | #692 |
| [`syn-s7-static-split`](syn-s7-static-split/product.toml) | `NEST-FORK` | 0705 | static split of the parameter AbsSegment, a parameter in the gap | #657, #411 |
| [`syn-s7-taskptr`](syn-s7-taskptr/product.toml) | `NEST-HUNT` | 0705 | TaskPtr and TaskCtrl2 records on LSM 3 | #527 |
| [`syn-text-initialvalue`](syn-text-initialvalue/product.toml) | `NEST-NAME` | 07B0 | TypeText with a de-DE InitialValue translation, utf-8 | #473 |
| [`syn-text-undeclared`](syn-text-undeclared/product.toml) | `NEST-SQUAWK` | 07B0 | TypeText non-ASCII default, no TextParameterEncoding | #416 |
| [`syn-union-bitfields`](syn-union-bitfields/product.toml) | `NEST-BITS` | 07B0 | 16-bit union of two types, sub-octet parameters packed by BitOffset | #604 |
| [`syn-union-default-range`](syn-union-default-range/product.toml) | `NEST-STRAY` | 07B0 | hidden union member, default outside its type | #405 |
| [`syn-user-memory`](syn-user-memory/product.toml) | `NEST-LARDER` | 07B0 | segment above 0xFFFF without SupportsExtendedMemoryServices | #472 |
| [`syn-user-memory-extmem`](syn-user-memory-extmem/product.toml) | `NEST-LARDERX` | 07B0 | segment above 0xFFFF with SupportsExtendedMemoryServices | #472 |
| [`syn-writerelmem-size`](syn-writerelmem-size/product.toml) | `NEST-QUILL` | 07B0 | LdCtrlWriteRelMem Size smaller than the RelativeSegment | #564 |
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
| `[product]` | `text`, `order_number`, `hardware_name`, `hardware_serial` (`00FA` + 8 hex digits), `bus_current` (mA); optional `hardware_version` (1), `rail_mounted` (false), `ip_enabled` (`IsIPEnabled`: a KNX IP interface built in, with `additional_addresses_count`; #455) | `Hardware`, `Product`, `Hardware2Program`, `CatalogItem` |
| `[application]` | `number` (0x2700 to 0x2AFF: 0x27xx System B, 0x28xx System 7, 0x29xx Secure, 0x2Axx RF and IP), `version` (one octet), `name`, `mask` (`07B0`; `57B0`, System B on KNX IP, or `27B0`, on KNX RF, merged procedure only, rendered with `MediumTypes="MT-5"` or `"MT-2"`; or `0705`/`0701` for System 7), `load_procedure_style` (`MergedProcedure` or `ProductProcedure` on 07B0, `ProductProcedure` on System 7), `address_table_max_entries`, `association_table_max_entries`; optional `translations` (`{ "de-DE" = "..." }` for the name); optional `schema` (`23`, or `11`: namespace `http://knx.org/xml/project/11` and `MinEtsVersion="4.0"` in all three files, the shape of the #448 vendor applications; `sign.py` then uses ETS's project-11 master data); optional `min_ets_version` (a string, `"4.0"`: `MinEtsVersion` apart from the schema's, #448); optional `additional_addresses_count` (`AdditionalAddressesCount`, the tunnelling addresses of an `ip_enabled` 07B0 device, #455); System 7 only: `address_table_segment`, `association_table_segment`, `com_object_table_segment` (the absolute segment each table starts in, offset 0; required) and `pei_type` (0) | `ApplicationProgram`, `AddressTable`, `AssociationTable`, `Languages` |
| `[application.options]` | any `Options` attribute of the KNX schema, e.g. `SupportsExtendedMemoryServices = true`, `ParameterByteOrder = "LittleEndian"` | `Options` |
| `[[segment]]` | `name`, `kind` (`relative`), `lsm`, `size`; optional `fill` (the initial octet, 0) | `RelativeSegment` with its `Data` |
| `[[parameter_type]]` | `name`, `kind`; `enum`: `size_bits`, `values = [{ value, text }]`; `number`: `size_bits`, `signed`, `min`, `max`; `float`: `encoding` (`DPT 9`, `IEEE-754 Single`, `IEEE-754 Double`; 16, 32, 64 bits), `min`, `max`; `text`: `size_octets`; `ip_address`: `address_type` (`HostAddress`, `SubnetMask`, `DefaultGateway`; 32 bits, the default a dotted quad); `color`: `space` (`RGB`, `HSV`; 24 bits, the default `#` and six hex digits) | `TypeRestriction`, `TypeNumber`, `TypeFloat`, `TypeText`, `TypeIPAddress`, `TypeColor` |
| `[[parameter]]` | `name`, `type`, `text`, `default`, and either `memory = { segment, offset, bit_offset }`, `union = { name, offset, bit_offset }` (a member at its offset in the union), `property = { object_index, property_id, offset, bit_offset }` (placed in an interface-object property, #604 row 30) or `virtual = true` (no memory, it only steers the Dynamic tree; #474); `bit_offset` counts from the octet's most significant bit, 0 to 7, so sub-octet parameters share an octet; optional `access` (`None`, `Read`, `ReadWrite`) and `legacy_patch_always` (#450); a text parameter also `initial_value` and `translations = { "de-DE" = { initial_value } }` (#473) | `Parameter` (`_P-<n>`, a union member `_UP-<n>`), one `ParameterRef` each; a translated `InitialValue` is a `TranslationElement` of the parameter in `Languages` |
| `[[parameter_ref]]` | `name`, `parameter` | a further `ParameterRef` of the parameter (`_P-<n>_R-<k>`, numbered after every parameter's own ref); blocks and chooses name it like a parameter (#563) |
| `[[union]]` | `name`, `size_bits`, `memory = { segment, offset, bit_offset }`; optional `default` (the member that is `DefaultUnionParameter`) | `Union` with its `Memory`, after the plain parameters |
| `[[parameter_calculation]]` | `name`, `language` (`JavaScript`), `inputs` and `outputs` (`[{ parameter, alias }]`), `lr_script`, `rl_script` | a `ParameterCalculation` (`_PC-<n>`) in the inline form: `RLTransformation`, `LRTransformation`, `LParameters`, `RParameters` with `AliasName`s (#427) |
| `[[com_object]]` | `number`, `name`, `text`, `function_text`, `size` (`"1 Bit"` to `"7 Bit"`, `"1 Byte"`, `"2 Bytes"` to `"14 Bytes"`), optional `dpt` (`"DPST-1-1"`), `flags` (of `C R W T U I`), `priority` (`Low`, `High`, `Alert`) | `ComObject`, one `ComObjectRef` each |
| `[[dynamic.block]]` | `name`, `text`, `parameters` (names), `com_objects` (numbers) | a `ParameterBlock` in the `ChannelIndependentBlock`; a parameter no block names is never shown (#448) |
| `choose` of a block | `[{ parameter, when = [{ test or default = true, parameters, com_objects, assign }] }]`; `assign = [{ target, source }]` (parameter names) | a `<choose ParamRefId>` inside the `ParameterBlock` after its refs, each `<when>` holding refs and com objects directly (#345), then its `<Assign TargetParamRefRef SourceParamRefRef>`s (#604 row 31) |
| `[[dynamic.channel]]` | `name`, `text`, `number` (a string), `[[dynamic.channel.block]]` (keys as `[[dynamic.block]]`) | a `<Channel>` (`_CH-<n>`) after the `ChannelIndependentBlock`, its blocks numbered after every other (#345) |
| `repeat` of a block | `[{ name, parameter, module, args }]`; `parameter` counts the instances, `args` maps every argument of the module to an `[[allocator]]` | a `<Repeat ParameterRefId>` after the block's chooses, holding one `<Module>` (`<module>_M-<n>`) with a `<NumericArg AllocatorRefId>` per argument (#449) |
| `[[allocator]]` | `name`, `start`, `max` | an `<Allocator>` (`_L-<n>`) in `<Allocators>` after the load procedures |
| `[[module_def]]` | `name`, `arguments` (`[{ name, allocates }]`), `[[module_def.parameter]]` (as `[[parameter]]` with `memory = { segment, offset, bit_offset, base }`, `base` an argument), `[[module_def.com_object]]` (as `[[com_object]]` plus `base`), `[[module_def.block]]` (`name`, `text`, `parameters`, `com_objects`) | a `<ModuleDef>` (`_MD-<n>`) in `<ModuleDefs>` between Static and Dynamic: `<Arguments>`, its parameters with `BaseOffset`, its `<ComObjects>` with `BaseNumber`, its parameter blocks (#449) |
| `[[dynamic.choose]]` | `parameter` (or a `[[parameter_ref]]`), `[[dynamic.choose.when]]` with `test` (as ETS writes it: `"1"`, `"0 2"`, `">=2"`) or `default = true`, and `[[dynamic.choose.when.block]]` (keys as `[[dynamic.block]]`) | a `<choose ParamRefId>` in the `ChannelIndependentBlock` after the blocks, each `<when>` holding its blocks, numbered after them (#474, #563) |
| `[[load_procedure]]` | `merge_id`, `ops = [{ op = "...", ... }]` | `LoadProcedure` |

Load ops: `LdCtrlRelSegment` (`lsm`, `size`, `mode`, `fill`),
`LdCtrlWriteRelMem` (`object`, `offset`, `size`, `verify`),
`LdCtrlMasterReset` (`erase_code`, `channel`) and
`LdCtrlWriteProp` (`object`, `prop_id`, optional `start_element`, `count`, `verify`,
`inline_data` in hex; without `inline_data` the value is what the parameters
placed in that property compose, so a parameter must be placed there). A System 7 product procedure
also takes `LdCtrlTaskPtr` (`lsm`, `init_ptr`, `save_ptr`, `serial_ptr`) and
`LdCtrlTaskCtrl2` (`lsm`, `callback`, `address`, `seg0`, `seg1`), and
`LdCtrlDelay` (`milliseconds`, #615). `{ op = "choose", parameter,
when = [{ test, ops }, { default = true, ops }] }` renders a `<choose
ParamRefId>` with its `<when>` branches inside the procedure (#411).
A 07B0 product procedure (#614) also takes `LdCtrlConnect`,
`LdCtrlDisconnect`, `LdCtrlUnload`, `LdCtrlLoad` and `LdCtrlLoadCompleted`
(`lsm`), and writes the program version by `LdCtrlWriteProp` with
`inline_data`, and takes `LdCtrlMapError` (`original_error`, `mapped_error`,
#604 row 38); its tables are relative segments the procedure allocates and writes
on LSM 1 to 3, with no code segment declared for them.

The schema reaches further than the generator does. These are reserved for
the catalogue products that need them (step 4 of #596), and a spec that uses
one stops with "part of the schema but no product uses it yet": masks other
than 07B0 (System 7 twins), absolute segments on 07B0, parameter
type kinds `time`, `raw`, VBScript calculations and the
`LRTransformationFunc` form with a `<Script>`, explicit com
object refs, and the load
ops `LdCtrlLoadImageProp`, `LdCtrlCompareProp` and `LdCtrlAbsSegment`, and
the connection and state ops in a merged procedure. An unknown key or op stops with an error naming it.

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

### Run variants

A run variant is another download of an existing product, not a product of
its own (#604, "Run variants"): `capture.py <name> --variant <variant>` runs
it in one knx-sim process, so ETS meets the device the previous download left,
and writes `captures/synthetic/<name>/<variant>/` with its own row and
manifest entry. The variants and their products are `VARIANTS` in
`tools/ets-sweep/synthetic/capture.py`:

| variant | products | the downloads | the row |
| --- | --- | --- | --- |
| `no-ga` | `syn-minimal` | the application, no group address linked (#542) | a flash row, as `defaults` |
| `links` | `syn-minimal` | the switch object linked to 1/0/1 and 1/0/2, the status object to 1/0/3, then the application (#478, #540) | `dir=` the model template with those links |
| `reload` | `syn-s7-0705`, `syn-s7-0701` | the application, then the same application again (#488) | `state=loaded` |
| `other-app` | `syn-s7-0705`, `syn-s7-0701` | a sibling of the same mask (`syn-s7-hidden-default`, `syn-s7-lsm5`), then this application (#488) | `state=loaded` |
| `partial` | `syn-minimal` | the application, then `Delay (s)` set to 500 in ETS's parameter editor and ETS's partial download (#543, #490) | `run=params base=` the first download, `dir=` the model template |
| `calc-input` | `syn-param-calculation` | `Delay (s)`, the calculation's input, set to 500, then the application (#427) | `dir=` the model template |
| `bare-restart` | `syn-master-reset` | the application into a device whose knx-sim config has `master_reset: refuse`: it answers the confirmed Master Reset with error code 2 (#611) | none: ETS 6.4.1 fails the download ("ConfirmedRestart ... fehlgeschlagen: UnsupportedEraseCode", 2026-10-31), no Basic Restart follows |

A variant directory holds the files of a `defaults` capture for its last
download (the one the row compares), and when there were earlier downloads,
`base.pcapng` and `base-requests.txt` with them; `sim.yaml` then replays
`base.pcapng` first. `objects.json` is the object table ETS showed before
the download, `params.json` what the parameter editor set. `model/` is the
model template of a row that plans with links or a parameter value
(`bussard.toml`, `devices/1.1.1.toml`, `groups.toml`): the oracle script
imports the product into a copy of it and pins the device (`dir=` in
`95-offline-oracle.sh`).

```
captures/synthetic/<name>/<variant>/base.pcapng        the earlier downloads of the same sim session
captures/synthetic/<name>/<variant>/base-requests.txt  their tool requests, replayed first by knx-sim
captures/synthetic/<name>/<variant>/model/             the model template of the row (links, parameters)
```

In CI, `synthetic_calibration.rs` replays `base-requests.txt` and then
`requests.txt` into one device, so a variant is checked against the device
ETS met. A `run=params` row (or `run=apply`) needs knx-sim: it runs in the
`sim-conformance` job (`test_offline_oracle_synthetic_sim_rows_pass_the_check`,
`KNX_SIM_BIN`), the other rows in the test job. The sim loop flashes products
and knows nothing of variants.

`partial` compares ETS's partial download with `bussard flash
--parameters-only`, the download `apply` runs for a parameter change: `apply`
itself refuses a device with no links ("refusing to plan an empty table
set", #542), which is what a defaults download leaves.

**A product change requires a re-capture.** A capture of other XML says
nothing about the committed product, so
`crates/bussard-cli/tests/it/synthetic_captures.rs` fails, ungated, when a
product's `xml/` digest differs from its manifest entry, and names the
`capture.py` command. A spec change that does not reach the XML (the `[doc]`
table) needs none.

**A re-capture after an XML change needs a version bump.** ETS keeps the
application it imported first under an order number and application version:
importing changed XML under the same version reports "imported", and the
download then uses the old program (#650; `syn-s7-lsm5` tested a stale 0x10
three times before its bump to 0x11). So raise `[application] version` with
any change that reaches `xml/`. `capture.py` refuses to capture a product
whose `xml/` digest differs from a manifest entry of it unless the version
is above the one in that entry's signed id, and names the version to bump
to. After the download it checks that ETS wrote the spec's version
(`PID_PROGRAM_VERSION` in `ops.txt`, or the LdCtrlTaskSegment record's
application id on System 7) and stops before copying anything if not.

A re-capture recomputes the row's options from the new verdicts (`expect=`,
`confirmed=`, `loadctl=`, `props=`) and from the product and variant
(`state=`, `dir=`, `run=`, `base=`, `lsm=`). Any other option on the
replaced entry's `row_options` (set by hand, e.g. `scope=`) is kept.

An IP-enabled product (`ip_enabled`, #455) has a KNX IP interface built in.
Its `sim.yaml` gives the device the KNXnet/IP parameter object (`knxnet:`,
as `sweep.py` does in the VM, since ETS aborts without one), and the knx-sim
replay builds the device with it. Its row plans against `defaults/model/`,
whose device file holds the `[knxnet]` table of the sweep project (DHCP, the
product text as the friendly name, the highest addresses of line 1.1): bussard
refuses to plan that download without one.

### Products without a capture

Some products cannot be captured in the sweep project, whose devices sit on
the TP line 1.1. They are rendered, imported by bussard and knx-sim, planned
by `bussard flash --dry-run` and, where knx-sim models the mask, flashed by the
sim loop; they have no `captures/synthetic/` directory, no row and no manifest
entry.

| product | why | ETS result (2026-10-31) |
| --- | --- | --- |
| `syn-ip-57b0` | mask 57B0 is a KNX IP device (`MT-5`); ETS will not place it on a TP line | "Import erfolgreich"; adding it to line 1.1: "ist nicht kompatibel zu dem Medientyp der Linie" |
| `syn-rf-27b0` | mask 27B0 is a KNX RF device (`MT-2`); ETS will not place it on a TP line, and knx-sim has no RF model (the sim loop skips it, `sim-loop-refusals.json`) | "Import erfolgreich"; adding it to line 1.1: "ist nicht kompatibel zu dem Medientyp der Linie" |

A product bussard refuses to flash, where the refusal is the finding it
exists for, is listed in `sim-loop-refusals.json` with the open issue and a
phrase of the refusal; the synthetic sim loop accepts that refusal and fails
once the product flashes.
A product whose mask knx-sim does not model (`syn-rf-27b0`) is listed there
too, with the loop's "is not simulated" phrase and a `note`; it goes when the
sim models the mask.

The tests `crates/bussard-prod/tests/it/synthetic_products.rs` and
`knx-sim/tests/synthetic_products.rs` zip every product's `xml/` with the stub
and read it, ungated; they need neither Python nor the VM.
