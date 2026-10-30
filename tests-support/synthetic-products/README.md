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
| [`syn-minimal`](syn-minimal/product.toml) | `SYN.min` | 07B0 | baseline | #596 |
<!-- catalogue:end -->

## Commands

```sh
uv run tests-support/synthetic-products/generate.py                # render every product's xml/
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
| `[application]` | `number` (0x2700 to 0x27FF), `version` (one octet), `name`, `mask`, `load_procedure_style`, `address_table_max_entries`, `association_table_max_entries`; optional `translations` (`{ "de-DE" = "..." }` for the name) | `ApplicationProgram`, `AddressTable`, `AssociationTable`, `Languages` |
| `[application.options]` | any `Options` attribute of the KNX schema, e.g. `SupportsExtendedMemoryServices = true` | `Options` |
| `[[segment]]` | `name`, `kind` (`relative`), `lsm`, `size`; optional `fill` (the initial octet, 0) | `RelativeSegment` with its `Data` |
| `[[parameter_type]]` | `name`, `kind`; `enum`: `size_bits`, `values = [{ value, text }]`; `number`: `size_bits`, `signed`, `min`, `max` | `TypeRestriction`, `TypeNumber` |
| `[[parameter]]` | `name`, `type`, `text`, `default`, `memory = { segment, offset, bit_offset }` | `Parameter`, one `ParameterRef` each |
| `[[com_object]]` | `number`, `name`, `text`, `function_text`, `size` (`"1 Bit"`), `dpt` (`"DPST-1-1"`), `flags` (of `C R W T U I`), `priority` (`Low`, `High`, `Alert`) | `ComObject`, one `ComObjectRef` each |
| `[[dynamic.block]]` | `name`, `text`, `parameters` (names), `com_objects` (numbers) | a `ParameterBlock` in the `ChannelIndependentBlock` |
| `[[load_procedure]]` | `merge_id`, `ops = [{ op = "...", ... }]` | `LoadProcedure` |

Load ops: `LdCtrlRelSegment` (`lsm`, `size`, `mode`, `fill`) and
`LdCtrlWriteRelMem` (`object`, `offset`, `size`, `verify`).

The schema reaches further than the generator does. These are reserved for
the catalogue products that need them (step 4 of #596), and a spec that uses
one stops with "part of the schema but no product uses it yet": masks other
than 07B0 (System 7 twins), `ProductProcedure`, absolute segments, parameter
type kinds `text`, `float`, `time`, `ip_address`, `raw`, a number's
`byte_order` (#403), parameter `access` and `union` (#405), explicit com
object refs, channels and `<choose>` in the Dynamic tree (#411), and the load
ops `LdCtrlMasterReset` (#546), `LdCtrlLoadImageProp`, `LdCtrlWriteProp`,
`LdCtrlCompareProp`, `LdCtrlAbsSegment` and the connection and state ops of a
product procedure. An unknown key or op stops with an error naming it.

Ids follow ETS: `M-00FA_A-<number>-<version>-0000` for the application, its
parts prefixed with it (`_RS-04-00000`, `_PT-<name>`, `_P-<n>`, `_P-<n>_R-<n>`,
`_O-<number>`, `_O-<number>_R-<n>`, `_PB-<n>`); hardware
`M-00FA_H-<serial>-<version>`, product `..._P-<order number>` and catalogue
item with ETS's escaping (`SYN.min` becomes `SYN.2Emin`). Every product shares
the catalogue section `M-00FA_CS-27` "bussard synthetic". Application numbers
start at 0x2700: KNX Virtual uses 0x25xx and the DA.tp clone 0x2600.

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
import-product` read a product with the stub. Two consumers need the real one:

- ETS 6.4 refuses the stub on import ("Die Eingabezeichenfolge hat das falsche
  Format", a FormatException reading the master data version, 2026-10-30).
  `sign.py` therefore replaces a stub with ETS's own
  `C:\ProgramData\KNX\XML\project-23\knx_master.xml` in the VM; the signed
  file is a build artefact and stays gitignored.
- bussard's flash plan of a `MergedProcedure` product splices the
  application's `LoadProcedure` blocks into the mask's load procedure from
  `knx_master.xml`. With the stub there is no template, and `bussard flash`
  of `syn-minimal` plans only the two application blocks (allocate and write
  LSM 4), which a device refuses. The signed file carries the real master
  data, so the oracle row of a signed product compares the full sequence.

## Render, sign, capture

1. Edit `<name>/product.toml`, run `generate.py` and `generate.py --catalogue`,
   commit the spec, `xml/` and this README.
2. `generate.py --zip <name>`, then sign it in the VM:
   `uv run tools/ets-sweep/synthetic/sign.py tests-support/synthetic-products/<name>/build/<name>.knxprod`
   (writes `<name>-signed.knxprod` next to it).
3. `generate.py <name> --signed-id tests-support/synthetic-products/<name>/build/<name>-signed.knxprod`.
4. Import into ETS and capture a download into knx-sim:
   `uv run tools/ets-sweep/synthetic/calibrate.py --knxprod <signed> --app <signed id> --search <order number>`
   (the sweep, the request fixture and the oracle row; see
   `tools/ets-sweep/README.md`).

The tests `crates/bussard-prod/tests/it/synthetic_products.rs` and
`knx-sim/tests/synthetic_products.rs` zip every product's `xml/` with the stub
and read it, ungated; they need neither Python nor the VM.
