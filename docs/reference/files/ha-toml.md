# ha.toml

`ha.toml` holds your overrides for `bussard ha-config`: group addresses to skip, and per-entity changes to platform, name, device class and extra addresses. You write it; it is optional. The output stays YAML, because that is what Home Assistant reads; only the overrides file is TOML, like the rest of the project.

## Example

```toml
# ha.toml: overrides for `bussard ha-config`.
[global]
default_platform_for_switches = "switch"   # or "light"
exclude = [
  "0/0/1",   # a single group address
  "8/",      # every address under main group 8
  "4/1/",    # every address under 4/1
]

[[entity]]
address = "1/0/1"
platform = "light"          # promote a derived switch to a light (or back)
name = "Kitchen ceiling"
device_class = "outlet"

[[entity]]
address = "3/1/5"
merge = ["3/1/6"]           # extra listening addresses

[[entity]]
address = "0/3/2"           # a climate entity, identified by its operation-mode address
name = "Büro heating"
merge = ["0/3/8"]           # for example a setpoint-shift status address
```

## Keys

| Key | Type | Meaning |
|---|---|---|
| `global.default_platform_for_switches` | `"switch"` or `"light"`, default `"switch"` | What a plain switchable actuator becomes. |
| `global.exclude` | array of strings | Group addresses, or prefixes ending in `/`, to skip entirely. An excluded address produces no entity and is not counted as unmapped. |
| `entity[].address` | string | The entity's primary group address: the one Home Assistant sends to for a switch, light or cover, or the state address it reads for a sensor or binary sensor. For a climate entity, the operation-mode command address. |
| `entity[].platform` | `"switch"` or `"light"`, optional | Override the derived platform. Only the switch and light promotion is offered. |
| `entity[].name` | string, optional | Override the derived name. |
| `entity[].device_class` | string, optional | Set or override the Home Assistant `device_class`. |
| `entity[].merge` | array of strings, optional | Extra group addresses to add to the entity. |

## Notes

- The file is parsed strictly, rejecting unknown fields and duplicate keys, so a typo is an error, not a silent no-op.
- Two `[[entity]]` entries for the same `address` are an error.
- How the overrides combine with the derivation (precedence, and what `merge` does on a climate entity) is on [Home Assistant](../home-assistant.md#overrides).

## Related

- [Home Assistant](../home-assistant.md): how entities are derived, and how these overrides apply.
- [Generate the Home Assistant config](../../how-to/home-assistant.md): the task, step by step.
- [Server commands](../commands/servers.md): `bussard ha-config` and its flags.
