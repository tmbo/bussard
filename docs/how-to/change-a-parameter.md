# Change a parameter

Change a device setting such as a channel mode, a run time or an alarm behaviour, and get it onto the device. Parameters are the settings ETS shows in a device's dialog; bussard keeps them in the device file.

## See the device dialog

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

`bussard device <address>` lists the device's channels, or its ETS pages for a device without channels. An inactive page says which parameter turns it on and whether that needs a full flash. `bussard device <address> <channel>` lists one channel or page: each parameter's key, current value, choices or range, and vendor default. Add `--toml` for lines to paste. The command reads files only and needs the device's product data.

## Set the parameter

Device-level parameters live in `[parameters]`, the others in their channel's table, keyed by the parameter's text:

```toml
[channel.a-1]
betriebsart = "Jalousie"
windalarm = "1"
```

The file stores only values that differ from the vendor default, and a choice takes its label. A colour takes `#` and two hex digits per component, such as `#FF8000`. Edit the value, then run `bussard validate`: with product data it checks that the key exists and the value is in range.

The assistant does the same with `knx_set_parameter`, using the keys `knx_show_device` lists. It changes the file only.

!!! note
    A re-import of an ETS project takes parameter values from ETS. If you still re-import, make the change in ETS too.

!!! note
    Some products compute a parameter from others with a script that ETS runs when you change an input. bussard does not run these scripts yet, so a computed parameter keeps its vendor default. Check such a device against ETS before you rely on the value.

## Preview it

Illustrative output, shortened:

```console
$ bussard plan 1.1.47
1.1.47 Jalousieaktor Kind 2
  channel a-1 (Fenster Süd)
    ~ betriebsart = Jalousie, was Rollladen
  ...
```

`plan` reads the device's parameter memory and lists each parameter that will change, in the vendor's words. It compares parameters only when it has the product data: the archive the lock pins in `products/`, or `--product <file.knxprod>`. Without it, a `note:` says the parameters were not compared.

To see what a device holds before you change anything, `reconstruct` decodes its parameters read-only:

```console
$ bussard reconstruct 1.1.12 --product heating.knxprod
...
parameters (application M-0083_A-0042-10-1234):
  1 parameter(s) differ from the vendor default:
      Night setback: 17 °C (default 18 °C)
  the device matches the model's parameters: block
```

## Write it with apply

!!! warning
    `apply` writes the device's parameter memory and restarts the device. A gateway that is not on your own machine needs `--allow-remote-gateway`.

```console
$ bussard apply 1.1.47
```

For most parameters `apply` is enough. It backs up the parameter memory to `captures/backups/parameters/`, writes only the octets that differ, restarts the device, and reads the memory back to verify. It refuses:

- a parameter that shows or hides a com object, because that changes the device's object table: it names the `bussard flash` it needs. Enable flags and data-length choices are usually such parameters.
- a device that runs another application than the product data describes: it writes the links and leaves the parameters alone, with a note.

`bussard flash <address> --parameters-only` runs the same parameter download on its own. To put the old values back, see [restore a parameter backup](back-up-and-replace.md).

## Write it with a full flash

When `apply` names a flash, run it:

!!! warning
    A full flash rewrites the device's application, parameters and links, with no backup. On a secure-capable System B device it usually starts with a factory reset that erases everything but the device's address. Try it on a spare device or the simulator first.

```console
$ bussard flash 1.1.12 --product heating.knxprod --gateway 127.0.0.1:3671
Flash plan for 1.1.12
  ...
  parameters  : 1 change(s):
      Night setback: 18 °C to 17 °C
  writes      : 312 byte(s) across 9 step(s), ~24 memory frame(s), est. 1.0s on TP1
  procedure   : 9 step(s); re-run with -v for the memory-level plan
```

The plan names each change with the value the device holds now. `flash` computes the full parameter memory from the vendor defaults plus your device file, so every value in the file reaches the device and every other one returns to its default. Without `--product` it uses the product data the lock pins.

Re-flashing the application the device already runs needs no `--force`. A device running a different application is refused unless you pass `--force`, which overwrites it with no backup.

## Check the read-back

After writing, `flash` checks that the application reads back as `Loaded`, then reads the parameter memory and compares it with the model as `plan` does. A parameter that still differs is named and the command exits non-zero. If a flash fails or stops midway, run the same `flash` again; it rewrites the application whole.

## Next steps

- [Change what a button does](change-a-link.md): links, undo and history.
- [Add a device](add-a-device.md): the first flash of a factory-fresh device.
- [Write commands](../explanation/write-commands.md): every refusal of `apply` and `flash`.
- [Programming commands reference](../reference/commands/programming.md): all `flash` flags.
