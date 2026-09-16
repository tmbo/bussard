# 🪽 bussard

A buzzard circles the field and sees everything move. `bussard` does that for a KNX building: an open-source CLI that programs, watches, and decodes the bus. Built so an LLM can manage your KNX configuration with you.

All the configuration for your KNX setup is stored in YAML files, ready for your chat agent to modify them, creating reviewable diffs. `bussard` pushes the changes to the devices over your KNXnet/IP gateway. ETS stays in the drawer for the things only ETS can do (certification, planning, the odd exotic device).

![How bussard fits together](docs/assets/overview.svg)

<details>
<summary>Text version of the figure</summary>

```
.knxproj (ETS export)      .knxprod (vendor data)
      | import                   | import-product
      v                          v
 +--------------------------------------+
 |  YAML model in git (knx/)            |   reviewable diffs,
 +------------------+-------------------+   humans + LLMs edit it
     write path     |     observe path
  validate . plan   |   monitor . capture
  apply . flash     v   read
 +--------------------------------------+
 |  bussard  <---MCP---  Claude / LLM   |
 +------------------+-------------------+
                    |
         KNXnet/IP gateway <-> KNX bus
```

</details>

## Quickstart

Have an ETS export? Import it and watch your bus decode itself:

```console
$ bussard import home.knxproj
imported 421 group addresses, 46 devices, 531 link entries → knx
$ bussard validate
0 errors, 51 warnings
$ bussard monitor
12:03:44.809  1.1.12 Taster Flur EG  → 1/0/1 Licht Flur         = On (1.001, obj "Taste 1")
12:03:44.981  1.1.7 Schaltaktor UV   → 1/0/2 Licht Flur Status  = On (1.001)
```

No ETS project? Start empty and adopt devices as you go:

```console
$ bussard init
Found gateway: KNX IP Interface (192.168.1.74:3671, IA 1.1.250)
Created a fresh KNX model in knx.
$ bussard adopt --product actuator.knxprod    # press the programming button
adopted 15.15.255 → 1.1.5
$ bussard flash 1.1.5 --product actuator.knxprod   # ETS-free application download
```

From there you can explore all the functionality of bussard:

```console
$ bussard read 4/1/11                # 21.4 °C (9.001)
$ bussard write 3/0/4 down           # the blind moves
$ bussard plan 1.1.5                 # diff the device's live tables vs the model
$ bussard apply 1.1.5                # write them: confirm, backup, verify
$ bussard ha-config --out ha.yaml    # Home Assistant config from the same model
$ claude mcp add knx -- bussard mcp --dir knx    # let Claude debug your bus
```

## Install

You will need a KNXnet/IP gateway (tunneling or routing). Optional but nice: your ETS project export (`.knxproj`) for an instantly named model, and also optionally vendor product data (`.knxprod`, free downloads from manufacturer sites) for commissioning new devices.

Grab a prebuilt binary from the
[latest release](https://github.com/tmbo/bussard/releases/latest)
(Linux x64, macOS arm64, Windows x64, each with a `.sha256` checksum), or build
from source:

```console
$ cargo install --path crates/bussard-cli
```

Package managers (Homebrew, winget, `curl | sh`) are planned.

## Safety

- A GA marked `protected: true` (wind alarm or central functions) is refused: the CLI needs `--force`. An LLM connecting to bussard over MCP has no override at all and cannot modify protected GAs.
- Every device write is plan-before-apply: bussard reads the live state, shows the diff, asks for confirmation, backs up, writes, and verifies.
- The MCP server has three tiers: passive (never transmits), read (default, rate-limited), write (opt-in via `--allow-writes`).

## Documentation

- [Reference](docs/reference.md): every command, flag, YAML field, and MCP tool.
- [How do I ...](docs/howto.md): recipes, from watching the bus to flashing a device.
- [Design](docs/DESIGN.md): architecture, feasibility, roadmap.
- [Home Assistant](docs/ha-config.md): how `ha-config` derives entities.
- [Product data](docs/product-data.md): `.knxprod` handling and the pointer index.

## Legal notes

Never commit `.knxproj` or `.knxprod` files: the application XML is the manufacturer's copyrighted work. You supply your own product files, free from manufacturer sites or the MyKNX catalogue ([details](docs/product-data.md)). `bussard` is an independent project, not affiliated with or certified by the KNX Association. KNX is a registered trademark of the KNX Association.

## License

[MIT](LICENSE)
