# Add a device

Bring a new device into the model and onto the bus, label devices on the bench, and start a model when there is no ETS project at all. Every device needs its vendor's product data (a `.knxprod` file); bussard downloads it from the vendor and never ships it.

## Get the product data

Shortened output:

```console
$ bussard import-product --order-number "AKK-0216.03"
Found in the product-data index:
  MDT — MDT Switch Actuator AKK (compact, REG)
  ...
Download this file? [y/N] y
Downloaded and verified 334088 bytes.
Stored vendor file (downloaded): knx/products/MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
```

The order number is printed on the device and shown by `bussard scan`. bussard checks the download's size and checksum before it keeps it. With a file you already have, run `bussard import-product <file.knxprod>`. `adopt` below fetches the file on its own when this step is skipped.

## Adopt the device

!!! warning
    `adopt` writes an individual address (the device's own bus address, such as `1.1.5`) to whichever device is in programming mode.

Shortened output:

```console
$ bussard adopt
  step 1/5  product data
  step 2/5  assign an address
device in programming mode: 15.15.255 (its current address)
adopt 15.15.255 → 1.1.5? [y/N] y
wrote 1.1.5; verifying…
  step 3/5  write the device file
  wrote knx/devices/1.1.5.toml
  step 4/5  wire the group objects
  ready-to-paste snippets (edit the group address to a free one):
    # ---8<--- groups.toml (inside `groups = [ … ]`)
    { address = "0/0/1", name = "Status channel A", dpt = "1.001" },
    # ---8<--- devices/1.1.5.toml
    [channel.a]
    status.send = "0/0/1"     # or `status.listen = ["0/0/1"]` for a receiving object
  step 5/5  summary

adopted 15.15.255 → 1.1.5
```

Press the device's programming button when `adopt` asks. It picks the next free address on your main line, or the one you pass (`bussard adopt 1.1.47`), confirms, writes and verifies it. It checks the device's order number against the product data and warns loudly on a mismatch. Then it writes the device file and prints snippets to paste.

Without a terminal it needs `--yes`. `--no-download` adopts without product data. A Data Secure device listed in your keyring keeps its address and is only read, never written.

What remains: paste and edit the snippets, then `bussard plan 1.1.5` and `bussard apply 1.1.5`. A factory-fresh device needs a first flash before its links work.

## Flash a factory-fresh device

!!! warning
    `flash` downloads the application program (the vendor software that decides what the device does) and takes no backup. It assumes the device is factory-fresh.

```console
$ bussard flash 1.1.5 --product MDT_KP_AKK_03_Switch_Actuator_V23.knxprod
Flash plan for 1.1.5
  application : M-0083_A-000D-23-5BFD MDT Switch Actuator AKK
  mask        : app 07B0 vs device 07B0 — compatible
  writes      : 512 byte(s) across 8 step(s), est. 2.4s on TP1
flash M-0083_A-000D-23-5BFD (2 memory write(s)) to 1.1.5? [y/N] y
...
flash verified: application program M-0083_A-000D-23-5BFD is Loaded on 1.1.5, and its parameters match the model
```

`flash` refuses before writing when the mask (the device's system generation) is not System B or System 7, the application's mask does not match the device, the vendor's load procedure has a step bussard cannot run, or (on System B) the device reports another manufacturer than the application's. It also refuses a device that already carries a different application, an unknown one, or a load state it cannot read; `--force` overrides that and destroys what is there. The same application again needs no flag.

If a flash fails midway, run it again: it rewrites the application whole. A device with a BCU access key needs `--bcu-key <HEX>`. `--dry-run` prints the plan without a gateway.

## Label devices on the bench

!!! warning
    `commission` writes the address of each device you press, and with `--flash` and `--apply` programs it too.

```console
$ bussard commission --line 1.1 --labels labels.csv
commission 2 device(s) on line 1.1 via 192.0.2.10:3671? [y/N] y
  press the programming button on Blind actuator (JAL-0810.03)
  assigned 15.15.255 → 1.1.7
1.1.7  Blind actuator  MDT JAL-0810.03  Ground floor / Living room
```

Devices that already answer at their address are left alone. For each other model device, `commission` asks for its programming button and checks the pressed device's order number against the model before it writes. The wrong module stops that device with both order numbers named, and the run moves on. Each commissioned device appends `address;name;order_number;floor;room` to the CSV for a label printer.

## Start without an ETS project

```console
$ mkdir knx && cd knx
$ bussard init
Searching for KNXnet/IP gateways on the local network...
Found gateway: KNX IP Interface (192.0.2.10:3671, IA 1.1.250)
```

`init` writes an empty model in the current directory. Discovery does not cross subnets; if it finds nothing, pass `--gateway <ip>`. Then build a model from what the devices carry (shortened output):

```console
$ bussard reconstruct --line 1.1 --out fresh
sweeping line 1.1.0–255 sequentially — estimated up to 13m38s on TP1
synthesized 9 group address(es) and 5 link(s)
```

`reconstruct` only reads. `--out` must be a new or empty directory. The result is a scaffold: names and types are placeholders, every link is recorded as `listen`, and devices it cannot read become stubs.

## Name the group addresses

Start the assistant's server with `--passive`, since nothing here transmits, and say "help me name the group addresses". It asks you to press a button, waits for the telegram, and proposes a type and a name such as "Kitchen ceiling light, switch". You confirm or correct it in chat, and only then does it write the model. At a terminal, `bussard learn` runs the same loop (see [Watch the bus](watch-the-bus.md)).

## Next steps

- [Change what a button does](change-a-link.md): wire the new device's objects.
- [Commission a line](commission-a-line.md): plan group addresses and program a whole line.
- [Device commands reference](../reference/commands/devices.md): every flag of `adopt` and `import-product`.
