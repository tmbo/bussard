# Change a parameter

Change a device setting such as a channel mode, a run time or an alarm behaviour, and get it onto the device. Parameters are the settings ETS shows in a device's dialog; bussard keeps them in the device file.

## See the device dialog

=== "In chat"

    An illustrative exchange:

    ```text
    You:        What can I set on the weather station logic, 1.1.202?
    Assistant:  (calls knx_show_device)
                9 of 35 pages are active. Universalkanal C4 is off; turning
                it on (Universalkanal C4 aktivieren = ja) shows 2 com
                objects, so the device then needs a full flash.
    ```

    `knx_show_device` lists the channels or pages, what each inactive one needs, and for one channel each parameter's key, value, choices and default.

=== "At the terminal"

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

    `bussard device <address>` lists the device's channels, or its ETS pages for a device without channels. `bussard device <address> <channel>` lists one channel or page: each parameter's key, current value, choices or range, and vendor default. Add `--toml` for lines to paste.

An inactive page says which parameter turns it on and whether that needs a full flash. Both forms read files only and need the device's product data.

## Set the parameter

=== "In chat"

    ```text
    You:        Set the blind actuator's channel Fenster Süd to Jalousie.
    Assistant:  (calls knx_set_parameter)
                Betriebsart on Fenster Süd is now Jalousie (was
                Rollladen). This changes your project only.
    ```

    `knx_set_parameter` takes the keys `knx_show_device` lists and checks the value against the product data. It refuses an unknown key and names the closest ones.

=== "At the terminal"

    Device-level parameters live in `[parameters]`, the others in their channel's table, keyed by the parameter's text:

    ```toml
    [channel.a-1]
    betriebsart = "Jalousie"
    windalarm = "1"
    ```

    A colour takes `#` and two hex digits per component, such as `#FF8000`. Edit the value, then run `bussard validate`: with product data it checks that the key exists and the value is in range.

The file stores only values that differ from the vendor default, and a choice takes its label. Either way only the file changes.

!!! note
    A re-import of an ETS project takes parameter values from ETS. If you still re-import, make the change in ETS too.

!!! note
    Some products compute a parameter from others with a script that ETS runs when you change an input. bussard does not run these scripts yet, so a computed parameter keeps its vendor default. Check such a device against ETS before you rely on the value.

## Preview it

=== "In chat"

    ```text
    You:        What would that write?
    Assistant:  (calls knx_plan_device)
                Jalousieaktor Kind 2, channel Fenster Süd: Betriebsart
                becomes Jalousie, was Rollladen. Shall I write it?
    ```

    `knx_plan_device` needs a server started with `--allow-programming`. To see what a device holds before you change anything, `knx_reconstruct_device` decodes its parameters read-only.

=== "At the terminal"

    Illustrative output, shortened:

    ```console
    $ bussard plan 1.1.47
    1.1.47 Jalousieaktor Kind 2
      channel a-1 (Fenster Süd)
        ~ betriebsart = Jalousie, was Rollladen
      ...
    ```

    To see what a device holds before you change anything, `reconstruct` decodes its parameters read-only:

    ```console
    $ bussard reconstruct 1.1.12 --product heating.knxprod
    ...
    parameters (application M-0083_A-0042-10-1234):
      1 parameter(s) differ from the vendor default:
          Night setback: 17 °C (default 18 °C)
      the device matches the model's parameters: block
    ```

The plan reads the device's parameter memory and lists each parameter that will change, in the vendor's words. It compares parameters only when it has the product data: the archive the lock pins in `products/`, or `--product <file.knxprod>` at the terminal. Without it, the plan says the parameters were not compared.

## Write it with apply

!!! warning
    The write changes the device's parameter memory and restarts the device. A gateway that is not on your own machine needs `--allow-remote-gateway`.

=== "In chat"

    ```text
    You:        Yes.
    Assistant:  (calls knx_apply_device)
                Written and verified: Betriebsart on Fenster Süd is
                Jalousie on the device.
    ```

=== "At the terminal"

    ```console
    $ bussard apply 1.1.47
    ```

For most parameters this is enough. The write backs up the parameter memory to `captures/backups/parameters/`, writes only the octets that differ, restarts the device, and reads the memory back to verify. A parameter that shows or hides a com object changes the device's object table, which a parameter write does not rewrite; enable flags and data-length choices are usually such parameters. That needs a full flash, below. A device that runs another application than the product data describes gets its links written and its parameters left alone, with a note.

`bussard flash <address> --parameters-only` runs the same parameter download on its own. To put the old values back, see [restore a parameter backup](back-up-and-replace.md).

## Write it with a full flash

!!! warning
    A full flash rewrites the device's application, parameters and links. On a System B device that supports Secure it usually starts with a factory reset that erases everything but the device's address. Try it on a spare device or the simulator first.

=== "In chat"

    ```text
    You:        Turn on Universalkanal C4 on 1.1.202 and write it.
    Assistant:  (calls knx_set_parameter, then knx_plan_device)
                This shows 2 com objects, so the device needs a full
                flash. It restarts and is offline for 30 to 50 seconds.
                The parameter memory is backed up first. Flash it?
    You:        Yes.
    Assistant:  (calls knx_apply_device, then knx_job_status until done)
                Flashed and verified: the device matches your project.
    ```

    The plan says `method: flash` and lists the com objects that appear or disappear. Your one yes covers the flash, and `knx_apply_device` runs it as a job. A device that runs an application bussard cannot identify is refused; overwriting it stays `bussard flash --force` at the terminal.

=== "At the terminal"

    When `apply` names a flash, run it. The terminal flash takes no backup.

    ```console
    $ bussard flash 1.1.12 --product heating.knxprod --gateway 127.0.0.1:3671
    Flash plan for 1.1.12
      ...
      parameters  : 1 change(s):
          Night setback: 18 °C to 17 °C
      writes      : 312 byte(s) across 9 step(s), ~24 memory frame(s), est. 1.0s on TP1
      procedure   : 9 step(s); re-run with -v for the memory-level plan
    ```

    The plan names each change with the value the device holds now. Without `--product` it uses the product data the lock pins. Re-flashing the application the device already runs needs no `--force`. A device running a different application is refused unless you pass `--force`, which overwrites it with no backup.

The flash computes the full parameter memory from the vendor defaults plus your device file, so every value in the file reaches the device and every other one returns to its default.

## Check the read-back

After writing, the flash checks that the application reads back as `Loaded`, then reads the parameter memory and compares it with your project as the plan does. A parameter that still differs is named, and the result is not verified. If a flash fails or stops midway, run it again; it rewrites the application whole.

## Next steps

- [Change what a button does](change-a-link.md): links, undo and history.
- [Add a device](add-a-device.md): the first flash of a factory-fresh device.
- [Write commands](../explanation/write-commands.md): every refusal of `apply` and `flash`.
- [Programming commands reference](../reference/commands/programming.md): all `flash` flags.
