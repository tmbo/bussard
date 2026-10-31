# bussard.toml

`bussard.toml` holds the connection to the bus, the optional lint rules, the import language and the Home Assistant connection. `bussard init` writes it; after that it is yours to edit. bussard never rewrites it, except to append a `[lint]` table when one is missing (`bussard groups reserve` does this the first time it runs).

## Example

```toml
[connection]
transport = "tunnel"              # "tunnel" | "routing"
gateway = "192.0.2.10:3671"     # host:port for tunnelling
# multicast = "224.0.23.12:3671"  # addr:port for routing; this is the default
# keyring = "house.knxkeys"       # deprecated: use the key store bussard.keys
# admit_tunnel_senders = true     # Data Secure: admit the key store's tunnelling
                                  # addresses as secure senders

[lint.topology]
max_devices_per_line = 64
[lint.topology.supply_ma]
"1.1" = 640
[lint.groups]
scheme = "floor-trade-block"      # or "function-floor"
feedback_pairing = true
name_pattern = "* * *"
[lint.groups.blocks]
light = 5
blind = 10
heating = 10

[import]
# language = "de-DE"              # text language of import

[home_assistant]                  # optional: the MCP server's Home Assistant tier
url = "http://homeassistant.local:8123"
token_env = "BUSSARD_HA_TOKEN"    # default; the token itself never goes here
config_path = "../ha/knx.yaml"    # the KNX YAML Home Assistant reads
```

## Keys

| Key | Type | Meaning |
|---|---|---|
| `connection.transport` | `"tunnel"` or `"routing"` | The transport used to reach the bus. |
| `connection.gateway` | string, optional | Gateway `host:port` for tunnelling. `--gateway` and `BUSSARD_GATEWAY` override it. |
| `connection.multicast` | string, optional | Multicast `addr:port` for routing. Default `224.0.23.12:3671`. |
| `connection.keyring` | path, optional | Deprecated: use the key store [bussard.keys](bussard-keys.md), which wins over it. The ETS `.knxkeys` keyring every bus command uses when `--keyring` is not given: for the KNXnet/IP Secure tunnel, the tool keys of the devices it lists, and the group keys. A relative path is resolved against the model directory. The password comes from `BUSSARD_KEYRING_PASSWORD`. Keep the keyring file itself out of git. |
| `connection.admit_tunnel_senders` | bool, default `false` | On a KNX Data Secure device, `plan`, `apply`, `flash` and `knx_apply_device` add every tunnelling address of the key store to the device's security individual address table (PID 54), so a secured `write` or `read` from bussard is accepted. |
| `lint.topology.max_devices_per_line` | integer, optional | The most devices one line may carry (the KNX TP limit is 64). Drives `L001`. |
| `lint.topology.supply_ma` | table line to mA, optional | Each line's power-supply budget. Drives `L002`. Declaring a line here also declares that it exists, which drives `L003`. |
| `lint.groups.scheme` | `"floor-trade-block"` or `"function-floor"`, optional | Which address level carries the floor and which the trade. The convention lints and `groups reserve` follow it. |
| `lint.groups.blocks` | table trade to size, optional | How many consecutive sub addresses each trade reserves per room. A trade that is absent is not part of the plan. |
| `lint.groups.feedback_pairing` | bool, default `false` | Require the feedback address the block layout reserves for each command address. |
| `lint.groups.name_pattern` | string, optional | A glob every group address name must match: `*` is any run of characters (including none), `?` exactly one, everything else literal. |
| `import.language` | string, optional | Overrides the language `import` derives texts and keys in. See [Text language](bussard-lock.md#text-language). |
| `home_assistant.url` | string | The Home Assistant instance. |
| `home_assistant.token_env` | string, default `BUSSARD_HA_TOKEN` | The environment variable that holds a long-lived access token. A `.env` supplies it only for a `BUSSARD_*` name. |
| `home_assistant.config_path` | path | The KNX YAML file Home Assistant reads, relative to the model directory unless absolute. |

## Notes

- **`[lint]` is opt-in.** Without it nothing extra is reported, so adding the feature cannot change an existing project. With it, `validate` runs the topology and convention rules `L001` to `L008` (see [Diagnostics](../diagnostics.md)).
- **Bus current for `L002`** comes from the product models in `.bussard/models/`, written by `import-product` from the `BusCurrent` in the `.knxprod` `Hardware.xml`. Devices with no product model contribute nothing and are counted in the warning.
- **`[home_assistant]`** is optional. With it, `bussard mcp --allow-home-assistant` registers the Home Assistant tools; without it the flag does nothing.
- **`admit_tunnel_senders`** is off by default. The reason it exists is in [Safety](../../explanation/safety.md).

## Related

- [Global options](../global-options.md): the flags that override `[connection]`.
- [Environment variables](../environment.md): `BUSSARD_GATEWAY`, `BUSSARD_KEYRING` and `BUSSARD_HA_TOKEN`.
- [Diagnostics](../diagnostics.md): the `L` codes the `[lint]` table turns on.
- [MCP tools](../mcp-tools.md): the Home Assistant tier `[home_assistant]` configures.
