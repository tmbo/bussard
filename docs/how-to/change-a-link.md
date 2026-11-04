# Change what a button does

Point a button at another light, check the change, write it to the device, and take it back if you change your mind. A link is the line in a device file that connects one com object (one input or output of the device, such as "rocker 1") to a group address.

## Edit the device file

=== "In chat"

    An illustrative exchange:

    ```text
    You:        Make the hallway rocker switch the porch light too.
    Assistant:  (calls knx_model_lookup, then knx_add_link)
                Rocker 1 on Hallway push button now switches Porch light.
                This changes your project only.
    ```

    `knx_model_lookup` finds the button and the light by their names, and `knx_add_link` writes the link into the device file. The assistant reads the change back as a sentence; nothing reaches the bus.

=== "At the terminal"

    Each device has a file, `devices/<address>.toml`. `bussard device` prints the lines for one channel, ready to paste:

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

    Change the group address on the com object's line. `apply` adds a group address that `groups.toml` does not define yet.

`send` is the address an object reports on; `listen` lists the addresses it obeys. Both forms change the same files.

## Check the project

=== "In chat"

    ```text
    You:        Is the project still valid?
    Assistant:  (calls knx_validate)
                No errors, 2 warnings.
    ```

=== "At the terminal"

    ```console
    $ bussard validate
    0 errors, 2 warnings
    ```

    `validate` exits non-zero on an error.

The check reads files only. A write is refused while the project has an error. Warnings do not block.

## Preview the write

=== "In chat"

    ```text
    You:        What would change on the blind actuator?
    Assistant:  (calls knx_plan_device)
                Jalousieaktor Kind 2, channel Fenster Süd:
                Langzeitbetrieb now listens on Jalousie Auf/Ab.
                Status position sends 0/1/4 instead of 0/1/9.
                Betriebsart becomes Jalousie, was Rollladen.
                Shall I write these 3 changes?
    ```

    `knx_plan_device` needs a server started with `--allow-programming`. It returns the plan with a digest that the write must present.

=== "At the terminal"

    ```console
    $ bussard plan 1.1.47
    1.1.47 Jalousieaktor Kind 2
      channel a-1 (Fenster Süd)
        + langzeitbetrieb now listens on 0/1/3 (Jalousie Auf/Ab)
        ~ status-position sends 0/1/4, was 0/1/9
        ~ betriebsart = Jalousie, was Rollladen
      unchanged: 3 objects, 41 parameters
      writes: address table (4 entries), association table (5 entries), 1 parameter octet
      backup: knx/captures/backups (tables) and knx/captures/backups/parameters (parameter memory)
    ```

    `+` is a link the device gains, `~` a value that changes, `-` an address only the device has.

The plan reads the device and shows what the write would change, in the device file's words. An address only the device has is often a stale link from an old ETS download; the write removes it.

A device that already matches has nothing to write. The plan never writes. It refuses a device with no links in your project, because writing that plan would empty the device.

## Write the change

!!! warning
    The write changes the device. Do your first writes against a spare device or the simulator. A gateway that is not on your own machine needs `--allow-remote-gateway`.

=== "In chat"

    ```text
    You:        Yes.
    Assistant:  (calls knx_apply_device)
                Written and verified: the blind actuator now matches your
                project.
    ```

    `knx_apply_device` writes only with the digest of a plan you said yes to, and refuses when a fresh read of the device no longer produces that plan. A long write runs as a job the assistant follows with `knx_job_status`.

=== "At the terminal"

    ```console
    $ bussard apply 1.1.47
    apply these 3 changes to 1.1.47 through 192.0.2.10:3671? [y/N] y
    ```

    `apply` validates the project, reads the device, shows the plan, and asks once. Without a terminal it needs `--yes`.

Both forms run the same write. It backs up the device's tables to `captures/backups/<address>-<timestamp>.json`, writes only what differs, and reads every write back. Both refuse before writing when the project has a validation error or the backup cannot be written.

At the terminal `apply` also refuses when:

- the product data the lock pins is missing or changed
- the device runs another application or mask than the lock pins (the message names the `bussard flash` it needs)
- a parameter change shows or hides a com object (see [Change a parameter](change-a-parameter.md))

In chat these become part of the plan instead. The assistant says the device needs its application loaded or a full flash, and your yes covers that too. Without the product data the plan writes the links only, and says so.

"Verified" means bussard read the tables and parameters back from the device and they match your project, not merely that the writes completed. The tables are rewritten whole, so writing again after a failure is safe. `apply` also reminds you when no installation-wide [backup](back-up-and-replace.md) exists yet.

## Undo a change

bussard saves a copy of the project files before every command that writes them or the bus, and before every edit the assistant makes. You do not need git.

=== "In chat"

    ```text
    You:        What did we change today?
    Assistant:  (calls knx_describe_change)
                Rocker 1 on Hallway push button now switches Porch light.
                Porch light changes type from 1.001 to 1.002.
                Nothing has reached any device yet.
    You:        Undo that.
    Assistant:  (calls knx_undo)
                Rocker 1 on Hallway push button no longer switches Porch
                light. Your project is back; the devices were never changed.
    ```

    `knx_describe_change` says in sentences what changed since the last snapshot, `knx_history` lists the snapshots, and `knx_undo` restores one.

=== "At the terminal"

    ```console
    $ bussard status
    2 pending changes since snapshot 20260922T101112Z-001 (2026-09-22T10:11:12Z)

    Rocker 1 on Hallway push button now switches Porch light.
    Porch light (0/0/4) changes type from 1.001 to 1.002.

    Nothing has reached any device yet.

    Next steps
      > bussard plan <ADDRESS>
        shows what writing a device would change
      > bussard apply <ADDRESS>
        writes it to the device
      > bussard undo
        puts the files back as they were at the snapshot
    $ bussard history
      1  20260922T100000Z-001  import home.knxproj (before writing the imported model)
         the first snapshot of the model
      2  20260922T101112Z-001  apply 1.1.5 → 192.0.2.10:3671 (before writing the device tables)
         Rocker 1 on Hallway push button now switches Porch light and 1 more
    $ bussard undo
    Restored the model files to snapshot 20260922T100000Z-001 (2026-09-22T10:00:00Z).
    The state before this undo is kept as snapshot 20260922T103000Z-001.

    Rocker 1 on Hallway push button (1.1.5) no longer switches Porch light (0/0/4).

    Run `bussard plan 1.1.5` and `bussard apply 1.1.5` to push this to devices.
    ```

    `bussard undo 1` picks a snapshot by number. `bussard show 2` prints what one snapshot changed, `bussard show 1 2` the change between two, and `bussard status --raw` the file-level diff.

Undo changes files only. The devices keep working as before until you plan and write them again. Without a choice it restores the newest snapshot that differs from your files. The undo is snapshotted too, so you can undo it. An edit made in an editor is recorded by the next command as an `external edit` snapshot.

## See what the assistant changed

```console
$ bussard status
1 pending change since snapshot 20260922T104500Z-001 (2026-09-22T10:45:00Z)

Living room blind actuator, channel B, now listens to Central down.
```

The assistant's edits go through the same history; `bussard history --json` shows which tool made each one. They reach a device only when pushed: by you with `plan` and `apply`, or by the assistant when its server runs with `--allow-programming`, each push after your yes to the plan. The assistant refuses a change to a `protected` group address outright. If you dislike a change, `bussard undo`. To run the server without edit tools, start it with `bussard mcp --no-model-edits`.

## Next steps

- [Change a parameter](change-a-parameter.md): run times, modes and other device settings.
- [Back up and replace](back-up-and-replace.md): a backup of every device before your first write.
- [Write commands](../explanation/write-commands.md): what each write command checks and refuses.
- [History commands reference](../reference/commands/history.md): `history`, `show` and `undo` in full.
