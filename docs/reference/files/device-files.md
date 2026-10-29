# Device files

A device file, `devices/<address>.toml`, holds one device: its name and location, its parameter values and its links to group addresses. `import` and `adopt` write it; after that it is yours in full. Parameters and objects sit in the table of the channel they belong to, keyed by the handles `bussard.lock` assigns.

## Example

`devices/1.1.47.toml`, based on a real import of a Jung 2300.21 SU switch and blind module, trimmed:

```toml
address = "1.1.47"
name = "Switch actuator, 2-gang / blinds actuator, 1-gang"
description = "Fenster"
product = "230021SU"                    # order number, printed on the device

[location]
floor = "DG"
room = "Kind 2 Süd"

[parameters]                            # device-level parameters (no channel)
regenalarm = "1"

[links]                                 # device-level objects (no channel)
regenalarm.listen = ["4/1/8"]

[channel.relaisausgaenge-1]             # handle from the lock
name = "Fenster Süd"                    # your label for the channel
bei-regenalarm = "schließen"            # parameter: scalar value
betriebsart = "Lüftungsklappe / Dachfenster"
langzeitbetrieb.listen = ["3/1/20"]     # command object: listens
kurzzeitbetrieb.listen = ["3/1/21"]
rueckmeldung-lueftungsklappen-dachfensterposition.send = "3/1/23"   # status object: sends
```

This device carries no `[security]` table, because Data Secure has not been activated on it. `application` and `replaced` are optional fields it happens not to set. `bussard device <address> <channel>` lists the keys a channel accepts, with their texts and ranges.

## Top level

| Key | Type | Meaning |
|---|---|---|
| `address` | string | The device identity, its individual address. Must match the file name (E002). |
| `name` | string | Display name. Required. |
| `description` | string, optional | Free text. |
| `product` | string, optional | The order number. The join key into the lock and the product data; needed for anything beyond links. |
| `application` | string, optional | Override of the application program the lock pins. |
| `replaced` | string, optional | RFC 3339 timestamp, written by `bussard replace`. |
| `[location]` | `floor`, `room` | Physical location. Optional. |
| `[security]` | `activated`, `secure_commissioning` | Intent only. What the device and project generated (`secure_capable`, `has_fdsk_certificate`, `sequence_number`) lives in the lock; key material never appears in either. |
| `[knxnet]` | table | The KNXnet/IP settings of an IP interface, or of a device with one built in, intent only. See [`[knxnet]`](#the-knxnet-table). |
| `[parameters]` | table | Device-level parameters. |
| `[links]` | table | Device-level objects. |
| `[channel.<handle>]` | table | One per channel: `name`, parameters, objects and parameter pages. |

`[parameters]` and `[links]` follow the same rules as a channel table, for the parameters and objects that belong to no channel.

## Inside a channel table

| Entry | Shape | Meaning |
|---|---|---|
| `name` | string | Your label for the channel. |
| `<key> = <value>` | string, integer or bool | A parameter. |
| `<key>.send` | string, one group address | The address the object transmits on. The object needs the T flag (E025). |
| `<key>.listen` | array of group addresses | The addresses the object accepts writes from. The object needs the W flag (E025). |
| `<key>.name` | string | Your override of the object's display name. |
| `[channel.<handle>.<page>]` | table | A parameter page holding parameters one level down. Exists only where the lock defines one for that channel. |

Every entry other than `name` is classified by the shape of its value, then checked against the lock:

- a string, integer or bool is a **parameter**;
- a table whose keys are a subset of `send`, `listen` and `name` is an **object** (a communication object, the device's input or output for one function);
- any other table is a **parameter page**.

Command objects `listen`; status objects `send`.

**Object keys.** An object key is either the key the lock assigns (`langzeitbetrieb`) or the bare object number (`144`). Both resolve to the same object; bussard writes the key from the lock when there is one.

**Parameter keys.** A parameter key is the key the lock assigns. When the same text would repeat within a scope, the lock assigns a longer key: page-qualified (`<page>.<key>`) or the escape hatch `<key>@<ref>`. bussard writes whatever the lock says, and reads through the lock. How keys are derived is in [Key derivation](bussard-lock.md#key-derivation).

A parameter key the lock does not list, a value you set for the first time, resolves through the product model:

- the key must equal the slug of exactly one parameter's text in the channel's scope (the module definition's parameters for a module channel, the application's own otherwise);
- that parameter must have exactly one ref in the model;
- the next save adds the key to the lock.

A key that resolves neither way is E023. A `<slug>@<ref>` escape key always resolves, lock or not; once the lock names that parameter, the next save writes the lock's key instead. A key the lock lists for one channel does not resolve in another channel's table. A device without a lock entry cannot resolve its parameters or object keys; validation reports E021 with the command that creates the entry (`adopt`, `import`, or `import-product` plus `import`).

**What the file shows.** The file holds only what ETS shows. ETS also stores values for parameter refs the configuration does not show (an inactive branch, the alternative of a shown ref) or never lets you edit (`Access="None"`). Those are the lock's `hidden[]`, not the file's.

## Without product data

The readable keys come from the vendor's product data (`.knxprod`), not from the ETS project. A device whose product data was never imported still gets a device file, but its channel handles are the vendor's channel ids and its objects are keyed by number. Its parameters can be neither checked nor flashed.

```toml
address = "1.1.1"
name = "Push Button Hallway"
description = "4-fold push button with status LEDs"
product = "PB-4F"

[location]
floor = "Ground Floor"
room = "Hallway"

[links]
40.send = "3/1/0"
40.name = "Spare Output"

[channel.CH-1]
name = "Rocker 1 - Hallway Light"
0.send = "0/0/0"
0.name = "Hallway Light - Switch"
1.listen = ["0/0/1"]
1.name = "Hallway Light - Status LED"
```

Once the product data is available, `import` or `adopt` rewrites the lock with keys, and the next save writes the readable form. The object numbers stay valid as keys either way.

## Parameter values

The file stores the value you mean. bussard accepts:

- a string: an enum label (`"Jalousie"`), an enum code (`"2"`), a number with unit (`"21 °C"`, `"15 min"`), or free text for a text parameter, which must fit the field in the program's text code page;
- an integer or a bool, converted to its string form.

A float is refused with a fix-it hint, because `1.10` and `1.1` cannot be told apart after parsing.

When the product model is available in `.bussard/models/`, the value is normalized to the vendor code: an enum label becomes its code, and a number with unit is checked against the range. Without the product model the string is kept as written, and validation reports that the value could not be checked (E026).

`flash`, `plan`, `apply`, `reconstruct` and `replace` resolve an enum label against the vendor program itself, read in the lock's `language` (see [Text language](bussard-lock.md#text-language)). A label matches, in this order:

1. the member's text in the lock's language;
2. else its untranslated text (the program's `DefaultLanguage`);
3. else its text in any other language the program carries, so a file edited from an English catalogue still loads under a German lock.

The first step with a match decides. A label two members share at that step is refused as ambiguous. A label no member carries is refused with the list of labels in the lock's language. `import-product` writes `.bussard/models/` in the same language, so the MCP `knx_set_parameter` check accepts the labels the device files carry.

## The `[knxnet]` table

A KNX IP interface or router carries the settings of its KNXnet/IP parameter object (interface object type 11) in a `[knxnet]` table:

```toml
[knxnet]
assignment = "dhcp"            # or "static"
address = "192.168.1.74"       # static only
netmask = "255.255.255.0"      # static only
gateway = "192.168.1.1"        # static only
friendly_name = "Bocklisch Alpha"
tunnels = ["1.1.22", "1.1.23", "1.1.24", "1.1.25", "1.1.26", "1.1.27", "1.1.28", "1.1.29"]
```

| Key | Type | Meaning |
|---|---|---|
| `assignment` | `"dhcp"` or `"static"` | How the interface gets its IP address. Default `"dhcp"`. |
| `address` | IPv4 string | With `static` only, and required there (E043). |
| `netmask` | IPv4 string | With `static` only, and required there (E043). |
| `gateway` | IPv4 string | With `static` only. |
| `friendly_name` | string | At most 30 ISO 8859-1 characters (E043). Absent: bussard leaves the device's name alone. |
| `tunnels` | array of individual addresses | The tunnelling slots, in order (`PID_ADDITIONAL_INDIVIDUAL_ADDRESSES`). |

The table is what you mean. What the device reports (the address, netmask and gateway in use, the assignment method in effect, the MAC address, the capabilities and the state) are device facts in `.bussard/facts/<address>.toml` (see [Model directory](../model-directory.md)), never in this file or in the lock.

Where the values come from:

- **`import`** reads the device instance's `<IPConfig>` and `<AdditionalAddresses>`. `Assign="Fixed"` is `static`, with the project's `IPAddress`, `SubnetMask` and `DefaultGateway`. Anything else, including no `Assign` at all, is `dhcp`, the ETS default, and the project's `IPAddress` (the last address ETS saw) is not kept. Each `<Address Address="22"/>` is a tunnel address on the interface's own line, in document order. The project carries no friendly name. The import summary prints one line per interface. Nothing is read from the device's `<Security>` element: the device authentication code, the management password and the tool key belong to the key store, never to the model.
- **`adopt`** of an IP interface reads the object and writes the table: the configured method (`dhcp`, with a note, when the device reports one the model does not spell, such as BootP), the static settings when `static`, the friendly name and the tunnels.
- **A re-import** keeps the file's table. A project whose tunnel addresses or static address differ is reported as a conflict (`knxnet.tunnels`, `knxnet.address`); `--theirs` takes the project's.

`validate` checks the table with E043 to E046 and, with the key checks, W047 (see [Diagnostics](../diagnostics.md)). `diff` and `status` describe a change as `Interface KNX IP Interface (1.1.200): tunnel address 1.1.30 added.`

!!! warning
    `plan` and `apply` of an interface with this table and no links write it to the device, and read each value back after the write. A field the table leaves out, and an empty `tunnels`, stays as the device holds it. Changing the assignment, the static address or the tunnel addresses of the interface the command tunnels through needs `apply --allow-self-reconfigure`.

Over MCP, `knx_set_interface` edits the table and `knx_plan_device` and `knx_apply_device` write it.

### A device with a KNX IP interface built in

A bus device whose application declares tunnelling addresses (`AdditionalAddressesCount`, for example the Zennio ALLinBOX family) has a KNXnet/IP parameter object too. A full `flash` of such a device writes it after the application and before the closing restart, as ETS does, and reads each value back:

- the routing multicast address 224.0.23.12, the routing TTL 32 and installation id 0, the values ETS writes for a project with its default backbone settings;
- `friendly_name`, required;
- the assignment method, which must be `dhcp`: no ETS capture shows what a download writes for a static address, so `static` is refused;
- `tunnels`, exactly as many as the application declares.

A `flash` whose device file lacks the table, or one of these values, is refused before anything is written. `import` fills `tunnels` and `assignment` from the project; add `friendly_name` by hand (ETS uses the device's name).

??? note "Details"
    The writes are property writes on the KNXnet/IP parameter object: the friendly name (PID 76), the tunnel addresses (PID 53), the static address set (PIDs 60 to 62) and the assignment method (PID 55).

## Related

- [bussard.lock](bussard-lock.md): the handles, keys and vendor facts this file is keyed by.
- [Device commands](../commands/devices.md): `device`, `adopt` and `import-product`.
- [Programming commands](../commands/programming.md): `plan`, `apply` and `flash`, which write these values.
- [Diagnostics](../diagnostics.md): E002, E021 to E026 and the `[knxnet]` codes.
