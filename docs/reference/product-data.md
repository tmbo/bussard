# Product data

Where bussard gets the vendor product data that tells it a device's objects, parameters and download procedure, where it keeps that data, and what it never does with it. Product data is the vendor's `.knxprod` file, or the copy inside your ETS project export.

## Where product data comes from

A `.knxprod` is a manufacturer's product database for one or more devices. You get it from:

- the manufacturer's service or download site (most publish `.knxprod` files free);
- the MyKNX catalogue (knx.org);
- an ETS export of a product you already have.

bussard reads these files; it never ships or redistributes them (see [The never-redistribute rule](#the-never-redistribute-rule)). To save you hunting for the right file, bussard ships a [pointer index](#the-pointer-index) that maps an order number to where its `.knxprod` can be downloaded. `bussard import-product --order-number <ORDER>` uses it to fetch and verify the file for a device you saw on the bus.

## The ETS export as source

An ETS 6 project export (`.knxproj`) carries the application program (the vendor's firmware configuration logic for one device type) of every product used in the project, unencrypted under `M-<manufacturer>/`. This is the only route for devices whose vendor ships product data solely as ETS3-era `.vd4` files, and it is convenient whenever the project already holds the exact application version a device runs.

- `bussard import-product <project>.knxproj` and `bussard import <project>.knxproj` extract each application program the model needs, once, into its own archive under `products/`. After that no command reads the export again.
- `bussard flash <ia> --product <project>.knxproj` still reads an export directly. The program is the one the lock pins for the device; `--application <application-id>` is needed only when the lock pins none.
- The generated models are the same, byte for byte, as from the vendor `.knxprod` when the versions match.

The export itself is never copied into the model: it is your project, and large. The extracted archive holds only `knx_master.xml`, the manufacturer's `Hardware.xml` and `Catalog.xml`, and the program (plus the programs its `Hardware2Program` lists next to it), copied byte for byte into a plain ZIP with fixed timestamps. A flash image built from the extracted archive is byte-identical to one built from the export. Extracting the same program from the same export again gives the same bytes, so a re-import does not change the lock.

## Reading product data at flash time

`flash`, `plan`, `reconstruct` and `adopt` read an archive in two steps:

1. the table of contents: the application program ids from the entry names (`M-XXXX/M-XXXX_A-….xml`), every `Hardware.xml` and `knx_master.xml`;
2. only the program the command selects, by `--application`, the model's application reference or the order number, together with the programs its `Hardware2Program` lists next to it.

A 15 MB project export with 30 programs costs one program parse instead of 30. When the ids alone do not settle the choice, every program is parsed, so a refusal reads as before. A lookup by order number reads the lock's `[[product]]` entries and parses nothing.

The table of contents and each parsed program are cached as JSON under `.bussard/products/`, so the next command reads them back instead of parsing the XML again. A cached program is the same value a fresh parse returns, so the images are byte-identical. The layout and `BUSSARD_PRODUCT_CACHE=off` are on [Model directory](model-directory.md#bussardproducts).

## What is inside a `.knxprod`

A `.knxprod` is a plain ZIP, with no encryption, unlike a password-protected `.knxproj`:

```
knx_master.xml            # global enums: manufacturers, mask versions, DPTs
M-XXXX/                   # one folder per manufacturer id, e.g. M-0004 (Jung)
  Hardware.xml            # order numbers → Hardware2Program → application refs
  Catalog.xml             # catalogue tree (not used by bussard)
  M-XXXX_A-….xml          # one ApplicationProgram per programmable variant
  *.signature             # RSA signatures, ignored
```

The signature files authenticate the archive to ETS. They stop third parties from forging files ETS will accept, but they do not stop reading a legitimately downloaded file, and bussard skips them.

From each application program bussard reads the identity (id, application number and version, mask version, name), the communication objects, the parameter types, the parameters with their defaults and memory locations, the code segments (metadata only) and the load procedure `flash` follows.

!!! note
    A text parameter is written in the code page the program declares (`TextParameterEncoding`, for example `iso-8859-15` or `utf-8`). A character outside that code page, or a text longer than the field, is refused. A program that declares no encoding is written in ISO 8859-1 (Latin-1), as ETS writes it; there a character whose octet differs between ISO 8859-1, Windows-1252 and ISO 8859-15 (the euro sign, for example) is refused.

    A colour parameter (`TypeColor`) is written as `#` and two hex digits per component: `#RRGGBB` for an RGB or HSV colour, `#RRGGBBWW` for RGBW. RGB and RGBW values are placed one octet per component in that order; an HSV parameter takes the RGB value and is stored as hue, saturation and value octets, as ETS converts it.

    Parameters a program computes with a `<ParameterCalculation>` script are not computed: bussard does not run the scripts, so such a parameter keeps its vendor default. ETS runs a script when one of its inputs changes, so a device configured in ETS can hold a computed value that `plan` can report as a difference.

??? note "Details"
    The program XML is streamed, never loaded as a whole document; 20 to 28 MB per program is normal. Com-objects are resolved from the `ComObject` base table and the `ComObjectRef` overrides into effective number, DPT, flags, size and text, the same way the `.knxproj` importer does. Parameter types cover `TypeNumber`, `TypeRestriction`, `TypeText`, `TypeFloat`, `TypeColor` (spaces RGB, RGBW and HSV) and `TypeNone`; any other `Type*` element is kept by name. A parameter-ref `Value` or `Access` overrides the parameter's own. Code segments (`RelativeSegment`, `AbsoluteSegment`) keep their id, size, address or offset and load-state machine; the binary payload is dropped. The `LdCtrl*` load procedure is parsed into a typed op list, and unknown ops are kept verbatim.

## The product store (`products/`)

`products/` holds every product archive the model depends on: vendor `.knxprod` files as downloaded or supplied, and the archives extracted once from an ETS export.

- **Retained, not a cache.** Vendor downloads can disappear and the export is used once, so bussard never regenerates anything in it.
- **Readable names.** The vendor's file name, or `<application-id>.knxprod` for an extracted program. A different file under a name already taken is stored with the first eight hex digits of its SHA-256 appended; nothing in the store is overwritten.
- **Pinned.** `bussard.lock` records each archive as a `[[product]]` entry and links each device to one (see [bussard.lock](files/bussard-lock.md)). Every use checks the file's SHA-256 against the lock before the archive is read.

**Committing it is your decision.** bussard does not git-ignore `products/`. It holds copyrighted vendor data, so a public repository should not carry it. A private one usually does, because a clone without it cannot flash, apply parameters, commission with `--flash` or replace a device until the archives are back.

**A missing or changed archive** refuses `flash`, `apply` (the parameters), `commission --flash` and `replace` before anything reaches the bus, with the lock's record and the way back:

```
product data for 1.1.12 (52911ST, products/M-0004_A-D141-22-151B-O000A.knxprod, sha256 9f1c0a3b7d2e…) is missing; restore it from your backup or version control, or re-import the ETS export: bussard import ../house.knxproj
```

The recovery depends on the archive's origin:

| Origin | Recovery |
|---|---|
| any | Restore the file from a backup or version control. |
| `index` | `bussard import-product --order-number <ORDER>` |
| `file` | `bussard import-product <file>` |
| `knxproj` | `bussard import <export>` |

An archive whose SHA-256 differs from the lock's is refused, naming both hashes; `bussard import-product <file>` re-pins it, which is a reviewable lock change. `plan` and `reconstruct` warn and read the links only.

**Overrides.** Every command that needs product data (`flash`, `apply`, `plan`, `reconstruct`, `commission --flash`, `replace`, `adopt`) resolves it from the lock and the store; `--product` and `--application` stay as overrides.

- An override that contradicts the lock (another archive hash, another application) is refused by `flash`, `apply` and `replace` unless `--force`, which uses it and pins the archive for the device. `plan` and `reconstruct` warn.
- `replace` needs no `--product`: the order number comes from the model and the application from the lock.
- `flash --product <export>.knxproj` needs no `--application` when the lock pins the device's program.
- `adopt` given an export stores it the way `import-product` does.

!!! note
    A model directory from an earlier bussard kept its archives in `vendor/`. The first command that reads the model moves every `vendor/*.knxprod` into `products/`, pins it (origin `index` when the pointer index knows its hash, else `file`), links the devices whose order number its catalogue carries, removes the empty `vendor/` with its old `.gitignore`, and generates `.bussard/models/`. A device whose product data only existed in an ETS export gets its archive on the next `bussard import` of that export.

## What `import-product` writes

`bussard import-product <file>`:

1. reads the `.knxprod`, or the `.knxproj` export;
2. stores a `.knxprod` byte-identically under `products/<original-name>` (an identical file already there is kept); from an export it extracts every application program into `products/<application-id>.knxprod`;
3. pins each archive in `bussard.lock` and links the devices it serves;
4. writes one product model per application program to `.bussard/models/<application-id>.yaml`.

With `--order-number` the downloaded file is stored the same way, with origin `index`. Running the command twice on the same file produces byte-identical archives, lock and models.

## Product data and the device files

The texts that make a device file readable come from the product data, not from the ETS project: the channel names, the parameter texts and enum labels, and the object functions. `import` and `adopt` derive the keys from them and record the mapping in `bussard.lock`, so a channel reads `betriebsart = "Jalousie"` and `langzeitbetrieb.listen = ["0/1/3"]`.

Without the product model, a device file still holds the device's name, location and links, but its channels are keyed by vendor ids and its objects by number, and its parameters can be neither checked nor flashed (see [Device files](files/device-files.md#without-product-data)). The lock carries what the rest of bussard needs (the object table, DPTs, flags, module offsets), so a checkout without `.bussard/models/` still validates, plans and decodes.

## The pointer index

The pointer index is a small JSON file, `data/product-index.json`, that ships with bussard. It holds pointers only: a download URL and a checksum for each product database, never the copyrighted file. `import-product --list` prints it; `--order-number` looks a number up.

!!! warning
    `--order-number` downloads from the vendor's site. bussard shows what it found and where it will download from, and asks first.

With `--order-number`, bussard:

1. normalizes the order number (trims whitespace, upper-cases) and looks it up in the index;
2. shows you what it found and where it will download from;
3. asks for confirmation: a terminal prompt, or `--yes-download` to skip it. Without a terminal it refuses unless `--yes-download` is given;
4. downloads to memory, with a hard 100 MiB cap;
5. verifies the download's byte size and SHA-256 against the index. A mismatch is a hard error: the file is not the one the index vouches for, perhaps because the vendor re-published it;
6. stores the verified file under `products/` and runs the normal import on it. When the entry names an `inner` file of a ZIP download, that `.knxprod` is stored instead of the ZIP.

The index covers about 900 product databases from MDT, Zennio, Lingg & Janke, Theben, Elsner, Siemens, ABB, Busch-Jaeger, Ekinex, Weinzierl and others, each verified by downloading it and computing its checksum. Most point at a bare `.knxprod`; some vendors serve a ZIP around it, and the checksum then covers the ZIP, which also covers the `.knxprod` inside. `BUSSARD_PRODUCT_INDEX` replaces the built-in index with your own, for a private mirror.

### Index schema

`data/product-index.json` is `{ "entries": [ … ] }`, each entry:

| Field | Type | Meaning |
|---|---|---|
| `manufacturer` | string | Human-readable name, for example `"MDT"`. |
| `manufacturer_id` | string | The KNX id as inside the `.knxprod`, for example `"M-0083"`. |
| `order_numbers` | [string] | Every order number this download serves, verbatim as in `Hardware.xml` (for example `"AKK-0216.03"`). One file often bundles a whole family. |
| `name` | string | Product or family display name. |
| `url` | string | Vendor-hosted download URL for the `.knxprod`. |
| `sha256` | string | Lower-case hex SHA-256 of the download. |
| `size` | number | Exact byte size of the download. |
| `filename` | string | The vendor's original file name; also the file name under `products/` unless `inner` is set. |
| `inner` | string, optional | For a ZIP download, the entry name of the `.knxprod` inside it that the entry points at. `import-product` stores that file under its own name. Needed when the ZIP holds several. |
| `application_ref` | string, optional | The application program ref an order number resolves to (documentation only). |
| `redistributable` | bool | Whether bussard may mirror the file itself. Always `false` for vendor-hosted copyrighted data. |
| `notes` | string, optional | Version and caveats. |

Order-number matching ignores case and surrounding whitespace but keeps interior separators: `AKK-0216.03` and `akk-0216.03` match, `AKK021603` does not, because `-` and `.` distinguish real KNX order numbers.

## The generated model files

`import-product` turns each application program into a model file under `.bussard/models/`: the object table, the parameters with their types, defaults and memory locations, the download procedure and the ETS dialog structure. The files are generated and carry a banner saying so; do not edit them. When the directory is missing, or a file is of an older format, the next command rebuilds it from the archives in `products/`.

## The never-redistribute rule

bussard never hosts, ships or mirrors vendor product data. `products/` holds the copyrighted `.knxprod` files you obtained or extracted from your own export, and `.bussard/models/` holds files derived from them. Whether `products/` is committed is your decision: a private repository is the usual case, and a public one should leave it out. This is the same footing as any interoperability tool: bussard reads legitimately obtained vendor files to interoperate.

## ETS version caveats

- **Schema namespace.** Application program XML declares its schema as the default namespace on the root `<KNX>` element, for example `http://knx.org/xml/project/23` for the ETS 6 generation. bussard parses by local element name, so a file from `/20`, `/21` or `/23` reads the same way, and it records the schema version in `identity.schema_version`.
- **Mask version drives behaviour.** `mask_version` (for example `07B0`, `0705`, `0701`, `0021`) tells the downloader whether the device is property-based (System B) or memory-based (older System 1 and 2). The reader only records it.
- **Modules.** Complex devices define objects and parameters inside reusable module definitions (`MD-…`) that the device instantiates (`MD-…_M-n_MI-n_…`). The model file lists the application-level refs; bussard maps a device's instances onto them by dropping the `_M-n_MI-n` instance segment, with the instance base offsets recorded in `bussard.lock`.
- **Translations.** Names and texts resolve to `en-US` when a translation is present, falling back to the file's default language otherwise, matching ETS. Device-file keys and labels follow the lock's `language` instead (see [Text language](files/bussard-lock.md#text-language)).

## Related

- [Device commands](commands/devices.md): `import-product`, `adopt` and their flags.
- [bussard.lock](files/bussard-lock.md): the `[[product]]` entries that pin each archive.
- [Model directory](model-directory.md): `products/`, `.bussard/models/` and the parsed-product cache.
- [How it works](../explanation/how-it-works.md): why product data matters to every write.
