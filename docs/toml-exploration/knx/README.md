# Example: the house model in the proposed TOML layout

This directory is `knx/` converted mechanically to the layout from round 7 of
[`../../toml-exploration.md`](../../toml-exploration.md). It exists to be
read, not to be loaded; bussard does not parse it yet. Regenerate it with
`python3 docs/toml-exploration/convert.py docs/toml-exploration/knx` from the
repository root.

```
bussard.toml        connection, hand-editable
groups.toml         the GA plan, hand-editable; ranges and groups as arrays
devices/1.1.4.toml  one file per device, hand-editable in full
bussard.lock        @generated: vendor facts for every device
.gitattributes      marks the lock as generated for GitHub
```

All 49 files parse with the `toml` crate.

## What a device file contains

Top level: `address`, `name`, `description`, `product` (the order number).
Then `[location]`, `[security]` where the device has it, `[parameters]` for
device-wide parameters, `[links]` for objects that belong to no channel, and
one `[channel.N]` table per channel holding that channel's parameters (scalar
values) and objects (`key.send = "…"`, `key.listen = […]`). The comment after
each channel header is the vendor's channel text, written once by import.

## What the conversion could and could not derive

The converter only had the YAML model and the six application programs
bundled in `home_test.knxproj`. The vendor data for the Jung devices (most of
the house) is not on this machine, and there is no `models/` directory. So:

- **Object keys.** For the 4 devices whose program is in the project file
  (1.1.30 and 1.1.202 among them), keys are the vendor's object function, or
  name plus function where the function repeats: `output`, `input`,
  `set-time`. For every other device the only text available was the ETS
  object name from `links.yaml`, which repeats inside a channel
  ("Venetian blind - Input" three times), so the key carries the object
  number: `venetian-blind-input-144`. With the product model these become
  `langzeitbetrieb`, `kurzzeitbetrieb`, `position`. 296 linked objects needed
  the number.
- **Parameter keys** are the slug of the ETS parameter *name*
  (`a12-betriebsart`), because the parameter *text* lives in the product
  model. Where a name repeats within its scope the key carries the ref as the
  escape hatch: `"bezeichnung@R-237"`, or the full ref for a module instance
  that has no channel. That is 396 of 1053 keys here, nearly all per-channel
  labels (`bezeichnung`, 98 times) and template selectors that the ETS block
  path would place under their channel. With the product model the file shows
  `[channel.1]` `bezeichnung = "A1/A2"`.
- **Parameter values** are the raw codes from ETS (`"2"`), not enum labels,
  for the same reason.
- **Channel numbers** come from the ETS `Number` attribute for the 4 devices
  with vendor data, and from the channel order within the device for the
  other 32 devices with channels (module channels in module order, then
  static channels), which is how ETS counts them. For the 12-fold actuators
  that gives `Relaisausgänge 1/2` = channel 1 through `23/24` = channel 12.
- **Channel names** are not in the device files. The ETS project only had the
  vendor texts, which the lock records; a user rename would add
  `name = "…"` under the channel header.

## Sizes

| | YAML today | TOML here |
|---|---|---|
| groups | 1326 | 452 |
| links | 1941 | folded into the device files |
| devices, 46 files | 5576, links separate | 2578, links included |
| lock | interleaved in the device files | 2435 |
