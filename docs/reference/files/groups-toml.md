# groups.toml

`groups.toml` is the group-address plan: every group address (the shared address a button sends on and an actuator listens to), its name and its datapoint type. `import` writes it from the ETS project; after that it is yours to edit, and `import`, `apply` and the MCP edit tools add the addresses a device file uses but the plan lacks.

## Example

```toml
project = "Haus"

ranges = [
  { address = "0",   name = "UG" },
  { address = "0/0", name = "Beleuchtung schalten" },
  { address = "1",   name = "EG" },
]

groups = [
  { address = "0/0/1", name = "Licht Büro aussen Schalten", dpt = "1.001" },
  { address = "0/0/2", name = "Licht Büro aussen Status",   dpt = "1.001" },
  { address = "0/3/1", name = "Heizung Büro Soll",          dpt = "9.001", protected = true },
  { address = "1/2/3", name = "Jalousie Küche Auf/Ab",      dpt = "1.008", secure = true, description = "Süd" },
]
```

## Keys

| Key | Type | Meaning |
|---|---|---|
| `project` | string, optional | Project name metadata. |
| `ranges[].address` | string | A main group (`"3"`) or a middle group (`"3/2"`). |
| `ranges[].name` | string | The range's name. |
| `groups[].address` | string | The group address. A duplicate is E020. |
| `groups[].name` | string | Display name. Hand-editable; survives re-import. |
| `groups[].dpt` | string, optional | Datapoint type (DPT, the value's encoding), for example `"1.008"`. Without it, `monitor` cannot decode the value (W011). |
| `groups[].description` | string, optional | Free text. |
| `groups[].protected` | bool, default `false` | A safety-critical address: the CLI refuses writes without `--force`, and MCP refuses outright. |
| `groups[].secure` | bool, default `false` | ETS runs the address with KNX Data Secure. Imported from the ETS project; the key itself lives only in the key store or keyring. A secured `flash` or `apply` refuses when the key store or keyring has no key for a linked `secure` address. |

## Notes

- **Quote the DPT.** A bare `1.001` is a float and is refused with a fix-it hint (see [Errors](errors.md)).
- **Order.** The file is ordered by address. bussard pads the `name` column so the file reads as a table; a hand edit that breaks the alignment is fine.
- **Duplicates.** A duplicate `address` is validation error E020, reported on both lines.
- **Missing addresses.** A group address a device file uses but `groups.toml` does not define is a warning during `validate`. `import`, `apply` and the MCP edit tools add it, named `<channel name> <object function>` with the object's DPT, and report it as added. `bussard groups reserve` adds addresses by plan.
- **Source.** The file a project was imported from is recorded in the lock as `source`, not here.
- **Changing `secure`.** `bussard groups secure <ga> on|off` sets the flag, the key store entry and the object flags together.

## Related

- [Project commands](../commands/model.md): `groups reserve`, `export-groups` and `import`.
- [Secure commands](../commands/secure.md): `groups secure`.
- [Device files](device-files.md): the links that use these addresses.
- [Diagnostics](../diagnostics.md): E001, E020, W011 and the `L` naming rules.
