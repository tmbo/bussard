# Device commands

The commands that find devices, address them, read what they hold and show what they can do: `scan`, `assign`, `describe`, `reconstruct`, `adopt`, `status`, `device` and `import-product`. Global options and exit codes are on [Global options](../global-options.md).

## `bussard scan [LINE]`

Scan a line for devices and compare what answers with the model. Read-only.

```console
$ bussard scan 1.1 [--from <N>] [--to <N>]
```

Each row shows the individual address (IA, the device's `area.line.device` address), mask version, manufacturer, order number, and whether the model knows it (known, unexpected, missing). When the sweep ends, stderr shows a summary such as `256 addresses in 8.4 s (absent by negative confirmation: 251, by timeout: 0)`.

| Flag / arg | Default | Meaning |
|---|---|---|
| `[LINE]` | `1.1` | The line to scan. |
| `--from <N>` | `0` | The first device number to probe (0-255). |
| `--to <N>` | `255` | The last device number to probe (0-255). |
| `--keyring <FILE>` | the key store | Its tunnelling users open the KNXnet/IP Secure tunnel, and a device it lists is identified over KNX Data Secure with its tool key. Unlisted devices are read in the clear. Password from `BUSSARD_KEYRING_PASSWORD`. |
| `--json` | off | Emit the rows as JSON, plus a `timing` object: `addresses`, `total_ms`, `absent_negative_confirmation`, `absent_timeout`, `refused`, and `per_address` rows `{address, ms, outcome}` with `outcome` one of `present`, `absent_negative_confirmation`, `absent_timeout`, `refused`. |

Behaviour:

- Addresses are swept one at a time, one management connection at a time.
- A Data Secure-activated device hides its mask from a plain read (mask `FFFF`). When the keyring lists the address, `scan` reads it over KNX Data Secure and shows the real mask; the row is marked `Data Secure activated` and JSON adds `"secure": "activated"`.
- Without a tool key the row keeps mask `FFFF` with the label `Data Secure activated (mask hidden), no tool key in the keyring` and `"secure": "activated_no_key"`. A key the device does not accept gives `"secure": "key_refused"`.
- A plain device's row has no `secure` field.
- `scan` never refuses a Data Secure device; it only labels it.

??? note "Details: how an absent address is ruled out"
    Most IP interfaces confirm every frame with an `L_Data.con`. When no device acknowledges a frame on TP1, the interface sends a negative confirmation within 22 to 45 ms, and `scan` takes it as proof that the address is absent. A gateway that sends none falls back to the ACK timeout and one repetition, 2 × 1.5 s per absent address. A present device is read with the same frames either way. On a line of 256 addresses with 5 devices that is about 8 s against about 12.5 minutes.

    The same rule applies to the other presence probes (`audit --live`, `reconstruct --line`, `backup`, `replace`, `commission`). Programming sessions and the readiness probe after a restart never use it: to them a negative confirmation only means "not up yet".

    On a Data Secure device the descriptor and properties are read over `A_SecureData` after the S-A_Sync handshake.

## `bussard assign [ADDRESS]`

Give the device in programming mode an individual address, then verify it at the new address.

!!! warning
    `assign` writes to a device. It acts on whatever device is in programming mode.

```console
$ bussard assign 1.1.47
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `[ADDRESS]` | next free on the line | The address to assign, e.g. `1.1.47`. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--json` | off | Print `{"schema", "from", "to", "gateway", "mask", "manufacturer_id", "serial", "secure", "programming_mode_cleared", "device_file"}`. |
| `--keyring <FILE>` | the key store | Its tunnelling users open the KNXnet/IP Secure tunnel, and its tool key for the new (else the old) address verifies a Data Secure-activated device. Password from `BUSSARD_KEYRING_PASSWORD`. |
| `--tool-key <HEX>` | | A raw 16-byte tool key (32 hex characters) for the verification of a Data Secure-activated device. Overrides the keyring's device entries; the keyring still opens the tunnel. For test or bench devices only: process arguments are visible to other users. |
| `--force` | off | Write the address although another device already answers at it. |

Behaviour:

- Checks on the bus that the address is free before anything is broadcast: it connects to the address and reads the device descriptor (step 1 of the standard's address write, Management Procedures 03_05_02 §2.3). An answer, or a disconnect, refuses the run and names the mask, manufacturer and order number of the device there, unless `--force`.
- Refuses when more than one device is in programming mode.
- A non-loopback gateway needs `--allow-remote-gateway`.
- Confirms on a terminal, naming the gateway. Without a terminal it refuses before loading the model unless `--yes` is given. An explicit address is not consent.
- Verifies by reading the device at its new address. "Verified" means the device answered there.
- A Data Secure-activated device is verified over KNX Data Secure with its tool key: `--tool-key` if given, else the keyring entry of the new address, else the entry of the old address.
- In the last case `assign` prints a note to re-export the keyring from ETS. The keyring lists tool keys by address, so `describe`, `flash`, `apply`, `scan` and `audit --live` find the key under the new address only after the re-export.
- Without any key, an activated device answers mask `FFFF`. The address is still verified, the output says `Data Secure activated (mask hidden), no tool key in the keyring`, and the stub device file records no mask.

## `bussard describe <ADDRESS>`

List a device's interface objects and every property's description: PID with a name when known, data type, element count, and read and write access levels. Read-only on the bus.

```console
$ bussard describe 1.1.4
```

Unlike `reconstruct`, `describe` does not resolve group tables. It shows the device's raw property set, which helps with commissioning and with an unknown device.

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device to introspect, e.g. `1.1.4`. |
| `--full` | off | Skip nothing: walk every object's property descriptions again, even when the device facts hold them. |
| `--keyring <FILE>` | the key store | The keyring holding the target's KNX Data Secure tool key. Required for a security-activated device. A keyring that does not list the target only opens the secure tunnel, and the device is read in the clear. The password comes from `BUSSARD_KEYRING_PASSWORD`, never a flag. |
| `--tool-key <HEX>` | | The raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`. A process argument is visible to other users, so do not use it on a real installation. |
| `--json` | off | Emit the report as JSON; see the fields below. |

Behaviour:

- The first `describe` stores the interface objects and property descriptions as device facts. A later run checks the device's mask and application id and, when both match, prints the stored descriptions; a note on stderr says the facts were reused. The report is the same either way.
- `--full` walks the descriptions again, `--refresh-facts` re-reads everything, and a changed mask or application id re-reads on its own.
- A KNX IP interface's KNXnet/IP parameter object is read on every run and printed as a `KNXnet/IP` section (`knxnet` in JSON), as `status <ADDRESS>` prints it.
- A security-activated device refuses plain management access. Pass its tool key with `--keyring` (or `--tool-key` for a test device) and `describe` runs over KNX Data Secure.
- A walk that finds no interface object after a successful descriptor read is a failure, not an empty device: `describe` exits 1 with the `--keyring` hint on stderr. System 1 (BCU1) devices have no interface objects and are exempt.
- The text output prints `KNX Secure (model):` and `KNX Secure (this run):` lines. No key material appears in text or JSON.

| JSON field | Present | Meaning |
|---|---|---|
| `address`, `mask`, `system_type` | always | The device and its mask version. |
| `objects` | on success | The interface objects and their properties. |
| `unsecured_management` | refused walk, no key | `"refused"`: the device answered the descriptor read but not the plain walk. |
| `secured_management` | refused walk, with a key | `"unanswered"`: the secured walk returned no interface object. |
| `error` | refused walk | The error message, with the KNX Secure hint. |
| `secure.model` | the model has a security block | What the import recorded: `secure_capable`, `activated`, `has_fdsk_certificate`. An export made before ETS activated the device says `activated: false`. `tables` (a Data-Secure-capable product) holds the capacities the product declares: `max_group_key_table_entries`, `max_individual_address_entries`, `max_p2p_key_table_entries`; a download that does not fit is refused before anything is unloaded. |
| `secure.device` | model security, a tool key, or a refused walk | What the device did in this run: `plain_management` (`answered`, `refused`, or `not_attempted` with a key) and `secured_management` (`used`, `not_attempted` without a key, `unanswered`, or `factory_key` when the device refused plain access and answered under its FDSK from the key store, issue #532). |

??? note "Details"
    `describe` sends `A_DeviceDescriptor_Read`, `A_PropertyValue_Read` (object discovery) and `A_PropertyDescription_Read`, never a write. Reusing the facts takes the descriptor read plus one property read: on a KNX Data Secure device about 4 requests instead of about 110. An activated device still answers the plain descriptor read and the PID 56 read, then refuses the interface-object walk.

## `bussard reconstruct [ADDRESS]`

Read a device's tables back over the bus and compare them with the model, or with `--line` sweep a line and write a fresh model. Read-only on the bus.

```console
$ bussard reconstruct 1.1.4
$ bussard reconstruct --line 1.1 --out rebuilt/
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `[ADDRESS]` | | The single device to read, e.g. `1.1.4`. Mutually exclusive with `--line`. |
| `--line <LINE>` | | Sweep a whole line, e.g. `1.1`, and write a fresh model. Requires `--out`. |
| `--from <N>` | `0` | First device number to probe in line mode (0-255). |
| `--to <N>` | `255` | Last device number to probe in line mode (0-255). |
| `--out <DIR>` | | Line mode only: the fresh model directory. Must be absent or empty; reconstruction never merges into an existing model. |
| `--product <FILE>` | the archive the lock pins | Single-device mode: the device's `.knxprod`, to read back and decode its parameter memory too. |
| `--application <REF>` | the lock's program | The application program id to decode with. Falls back to the order number's program, then the sole application. |
| `--no-parameters` | off | Single-device mode: read the links and tables only. No product is parsed and no parameter memory is read, which on a large parameter segment is most of the time. Conflicts with `--product` and `--application`. |
| `--keyring <FILE>` | | Single-device mode: the keyring holding the target's KNX Data Secure tool key. Required for a security-activated device; password from `BUSSARD_KEYRING_PASSWORD`. |
| `--tool-key <HEX>` | | Single-device mode: the raw 32-hex-character tool key, for a simulator or bench device. Conflicts with `--keyring`. |
| `--json` | off | Emit the result as JSON; `table_source` reports per table how it was read. |

Behaviour:

- System B (mask `07B0`) only. In line mode other masks are recorded as stubs; in single-device mode they are refused.
- The comparison is by group-address set per object. Send or listen direction cannot be recovered from the address and association tables alone.
- Without `--product`, the archive `bussard.lock` pins in `<dir>/products/` is used. A pinned archive that is missing or changed prints a warning, and the parameters are not read.
- A KNX Data Secure-activated device without its tool key stops with "mask FFFF (System ?) ... can: describe only" plus the `--keyring` hint. With `--keyring` or `--tool-key`, every read runs over KNX Data Secure and the device reports its real mask.

??? note "Details: how tables are read"
    Each table's entry count comes from its `PID_TABLE` property. The entries are read from memory (at the table's `PID_TABLE_REFERENCE` address, `A_MemoryExtended_Read` or `A_Memory_Read` in chunks of up to 228 octets, 215 under Data Secure) when that takes fewer requests than `PID_TABLE` reads of 15 elements, else through `PID_TABLE`. A table of 1,333 associations takes 25 memory reads instead of 89 property reads. The memory read falls back to `PID_TABLE` when the reference is missing, the device refuses or does not answer, or the memory count word disagrees with the property count. `table_source` says `property (PID_TABLE)` or `memory (PID_TABLE_REFERENCE)`. `plan`, `apply`, `backup` and the MCP plan tool read tables the same way.

## `bussard adopt [ADDRESS]`

Bring a new device from programming mode into the model: product data, address assignment with an order-number cross-check, a device file with its `bussard.lock` entry, and snippets for `groups.toml` and the device file. `adopt` prints the `flash` command; it does not flash.

!!! warning
    `adopt` writes the individual address of the device in programming mode.

```console
$ bussard adopt 1.1.47
```

| Flag | Default | Meaning |
|---|---|---|
| `[ADDRESS]` | next free on the line | The address to give the device, e.g. `1.1.47`. A Data Secure device keeps the address ETS gave it. |
| `--product <FILE>` | the archive the lock pins, else fetched | The vendor `.knxprod` for the new device. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--yes-download` | off | Download missing vendor product data without asking. Without a terminal and without this flag nothing is downloaded; the missing order numbers are listed. |
| `--no-download` | off | Never download product data; adopt without it and say where to get it. |
| `--force` | off | Write the address although another device already answers at it. |

Behaviour:

- Before writing a new address it checks on the bus that the address is free, as `assign` does, and refuses when a device answers there, unless `--force`.
- A non-loopback gateway needs `--allow-remote-gateway`.
- Confirms the address write on a terminal. Without one it refuses before loading the model unless `--yes` is given, and the wizard's choices take their defaults (the first application of a multi-application product).
- A device already at the target address gets no address write.
- Without `--product`, `adopt` reads the order number off the device and uses the archive the lock pins in `<dir>/products/`. When there is none it looks the order number up in bussard's pointer index (the one `import-product --order-number` uses), asks once, downloads and verifies the file, imports it and continues.
- An order number the index does not know is adopted without product data (identity and links by number), with a sentence that says where to get the file. `BUSSARD_PRODUCT_INDEX=<file.json>` points at another index of the same shape.
- A KNX IP interface's KNXnet/IP parameter object is read and written into the device file's `[knxnet]` table (assignment, static settings, friendly name, tunnel addresses); the rest goes into the device facts. A table the model already holds stays.

**A Data Secure-activated device reads only.** When the keyring (`--keyring`, else `BUSSARD_KEYRING`, else `connection.keyring`) lists the device in programming mode, `adopt` treats it as a device ETS has commissioned:

- It keeps the device at its address and refuses another target before anything is sent, because the keyring looks tool keys up by address. To re-address, run `assign --keyring`, then re-export the keyring.
- It writes nothing to the device: no address, no programming-mode write, nothing to the security object. The device stays in programming mode until you press its button.
- It reads the device, its link tables, its parameters and its security object over KNX Data Secure with the keyring's tool key, as `reconstruct` does.
- The device file gets the links (an object with the `T` flag sends on its first associated address and listens on the rest; others listen), the parameters that differ from the vendor defaults, and `[security] activated = true, secure_commissioning = true`.
- The lock gets `secure_capable = true`, the keyring's sequence number and the device's list of trusted senders as `secure_senders`. A later secured `flash` or `apply` writes those senders back next to the ones the links imply.
- Secured objects and the linked group addresses the keyring holds a key for are marked `secure`. A group address the model lacks is created as `GA <address> (adopted from <ia>)`. Where the device and the keyring disagree, the summary says which way.
- `bussard plan <ia>` right after reports `matches the model`.
- An activated device the keyring does not list (mask `FFFF`) fails with "the keyring … has no tool key for <ia>" and a hint to re-export the keyring. No device file is written.
- Activating a factory-fresh Secure device from its FDSK certificate, re-keying it or turning Data Secure off stays with ETS.

??? note "Details"
    The secure read covers the descriptor and identity, the link tables, the parameter memory, and the security object's group-object security flags (PID 61) and security individual address table (PID 54). When PID 61 is not readable, the keyring's group keys decide which objects are secure. The key tables (PID 53, PID 56) are write-only and never read. The only bus traffic is the programming-mode broadcast, the free-access `A_Authorize_Request` every read-only session sends, and these reads. The KNXnet/IP object is object type 11.

## `bussard status [ADDRESS]`

Show what changed in the model since the last history snapshot, as plain sentences. With an address, read that device instead.

```console
$ bussard status
Rocker 1 on Hallway push button (1.1.5) now switches Porch light (0/0/4).
```

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Emit the change set as `{"schema", "base": <snapshot id>, "changes": [...]}`. With `ADDRESS`: `{"schema", "address", "name", "mask", "system_type", "identity", "knxnet", "model_knxnet", "knxnet_drift"}`. |
| `--raw` | off | Print the file-level diff instead of the sentences. Not with `ADDRESS`. |

Behaviour without an address:

- Reads files only; nothing here has reached a device. Always exits 0.
- With no snapshot yet it says so and stops.

Behaviour with an `ADDRESS`:

- Reads the device's mask and identity and compares them with `bussard.lock`. Read-only.
- For a KNX IP interface or router it also reads the KNXnet/IP parameter object: the IP address in use and how it was assigned, the configured method and static settings, the MAC address, the friendly name, the KNX address, the tunnelling addresses, the routing multicast address, the capabilities and the device state (`ok`, `KNX fault`, `IP fault`).
- What it read is stored with the device facts and compared with the device file's `[knxnet]` table; each difference is one line.
- A device without the object says so, and is recorded with `no_knxnet = true` in its facts, so the next command does not probe again until the facts are read anew.
- A KNX Data Secure-activated device needs its tool key, as for `describe`.

??? note "Details"
    The object (type 11) is found in the object table, else in the device object's `PID_IO_LIST`, else with one `A_PropertyExtValue_Read` of object type 11, instance 1, for interfaces that list it in neither. The last two wait at most 1 s for an answer, and a device that leaves them unanswered keeps its connection. Only descriptor and property reads are sent, never a KNXnet/IP Secure property (PID 91 and up).

## `bussard device <ADDRESS> [CHANNEL]`

Show what a device can do, in its device file's words. Files only: the data comes from `bussard.lock` and the product model under `.bussard/models/`.

Illustrative output, shortened:

```console
$ bussard device 1.1.202
...
pages (ETS parameter blocks, in ETS order):
  page                         text                          params  objects  state
  allgemein                    Allgemein                     12      2        active
  universalkanal-c3-funktion   Universalkanal C3: Funktion   3       0        active
  universalkanal-c4-funktion   Universalkanal C4: Funktion   48      2        inactive: set universalkanal-c4-aktivieren = "ja.." (default "nein"); shows 2 object(s); enabling it shows com-objects, so it needs `bussard flash 1.1.202` ...
...
summary: 26 of 35 pages inactive: 1 Datum und Uhrzeit; 7 Universalkanal C4: Funktion .. Universalkanal C10: Funktion; ...
```

With `--toml` it prints paste-ready device-file TOML:

```console
$ bussard device 1.1.47 a-1 --toml
# devices/1.1.47.toml: Jalousieaktor Kind 2; uncomment what you want to set

[channel.a-1]   # Jalousie 1
name = "Fenster Süd"
betriebsart = "Jalousie"   # Betriebsart: Rollladen | Jalousie
# fahrzeit = "60"   # Fahrzeit: 1..600
langzeitbetrieb.listen = ["0/1/3"]   # CWU Langzeitbetrieb, Jalousie 1, 1.008
# status-position.send = ""   # CRT 5.001
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device, e.g. `1.1.47`. |
| `[CHANNEL]` | | The channel or page to list in detail (its handle, id or number, or a page handle), or `device` for the device-level `[parameters]` and `[links]`. |
| `--toml` | off | Print the paste-ready device-file TOML instead of the table. |
| `--json` | off | Emit the view as JSON (`channels`, `device_level`, `blocks`, `inactive_channels`, `summary`, `scope` with `parameters` and `objects`, `notes`). |

Behaviour:

- Without a channel it lists the channels: the handle the file uses (`[channel.<handle>]`), the vendor's number and text, your name for it, and how many parameters and objects each has.
- With a channel it lists that channel's parameters (key, current value, the choices or the range, whether it is at the vendor default, the vendor's text) and objects (key, number, text and function, DPT, flags, what it sends and listens on).
- Without product data it says so and lists what the lock has.
- An application without channels of its own (none, or one generic channel) is also listed by ETS parameter page, in ETS order, with a handle per page.
- A page the configuration does not show is marked `inactive`, with the parameters that enable it (outermost first, each with the value that shows the page and its default) and the objects it would show.
- The inactive marker says how the change reaches the device: a page that shows com-objects needs `bussard flash <ia>`; one that does not is pushed with `bussard apply <ia>` or `knx_apply_device`.
- A device with channels lists the channels its configuration does not show under `inactive channels`, with the same marker. The `summary` line counts what is inactive.
- `bussard device <ia> <page>` lists one page: for an active page the parameters and objects on it, for an inactive one the parameters it would show at their defaults and its objects.
- In `--toml`, lines for what the file sets are live; everything else is commented with the vendor default and the choices. Every parameter the current configuration shows is listed, including ones at their default that ETS never stored.
- A parameter that shows or hides com-objects (an enable flag, a data length) is set like any other, but reaches the device only through a full `bussard flash <ia>`: `apply` refuses it.
- An object without links is suggested as `listen` when it takes commands (W flag) and as `send` when it reports (T flag).

??? note "Details"
    Pages are the product model's `<ParameterBlock>` entries (`blocks`, see [Product data](../product-data.md)). A page behind the same switch as an earlier one, with a title of another shape, is folded into it (`includes`); a page nested in an inactive one is not listed. Pages and channels inside a module definition are not analysed. The summary groups titles that differ only in their numbering. Where the application's parameter ref overrides the parameter's default, that override is the default shown. A channel with only `Access="None"` parameters and no objects is not listed.

## `bussard import-product [FILE]`

Import vendor product data (`.knxprod`): store it under `<dir>/products/`, pin it in `bussard.lock`, and generate one product model per application program under `<dir>/.bussard/models/`.

```console
$ bussard import-product <FILE>
$ bussard import-product --order-number <ORDER> [--yes-download]
$ bussard import-product --list
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `[FILE]` | | The `.knxprod` or `.knxproj` file to import. |
| `--order-number <ORDER>` | | Look the `.knxprod` up in the pointer index by order number and download it from the vendor, with confirmation. |
| `--yes-download` | off | Download without asking. Without a terminal and without this flag the download is refused. Only meaningful with `--order-number`. |
| `--inner <NAME>` | | Import one named inner archive from a multi-product `.knxprod` instead of every one it contains. |
| `--list` | | List the product-data pointer index and exit. |

Behaviour:

- An ETS project export (`.knxproj`) works as a source too: each application program is extracted once into `<dir>/products/<application-id>.knxprod`, and the export itself is not copied.
- Downloads are verified against the index by byte size and SHA-256. A mismatch is a hard error.
- Order-number matching ignores case and whitespace but keeps interior separators: `AKK-0216.03` matches `akk-0216.03`, not `AKK021603`.

## Related

- [Find what you have](../../how-to/find-what-you-have.md): audit, scan, describe and reconstruct in practice.
- [Add a device](../../how-to/add-a-device.md): adopt and flash a new device.
- [Write commands](../../explanation/write-commands.md): the rails of `assign` and `adopt`.
- [Product data](../product-data.md): the product store and the pointer index.
