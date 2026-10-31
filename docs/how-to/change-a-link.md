# Change what a button does

Point a button at another light, check the change, write it to the device, and take it back if you change your mind. A link is the line in a device file that connects one com object (one input or output of the device, such as "rocker 1") to a group address.

## Edit the device file

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

Change the group address on the com object's line. `send` is the address an object reports on; `listen` lists the addresses it obeys. `apply` adds a group address that `groups.toml` does not define yet. Or ask the assistant: "make the hallway rocker switch the porch light". Its edit tools change the same files and read the change back to you as sentences before you agree. They never touch the bus.

## Check the model

```console
$ bussard validate
0 errors, 2 warnings
```

`validate` reads files only. It exits non-zero on an error, and `apply` refuses to write while one exists. Warnings do not block.

## Preview the write

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

`plan` reads the device and shows what `apply` would write, in the device file's words. `+` is a link the device gains, `~` a value that changes, `-` an address only the device has. A `-` line is often a stale link from an old ETS download; `apply` removes it.

A device that already matches prints `1.1.47 matches the model; nothing to write`. `plan` never writes. It refuses a device with no links in the model, because writing that plan would empty the device.

## Write the change

!!! warning
    `apply` writes the device. Do your first writes against a spare device or the simulator. A gateway that is not on your own machine needs `--allow-remote-gateway`.

```console
$ bussard apply 1.1.47
apply these 3 changes to 1.1.47 through 192.0.2.10:3671? [y/N] y
```

`apply` validates the model, reads the device, shows the plan, and asks once. Then it backs up the device's tables to `captures/backups/<address>-<timestamp>.json`, writes only what differs, and reads every write back. It refuses before writing when:

- the model has a validation error
- the product data the lock pins is missing or changed
- the device runs another application or mask than the lock pins (the message names the `bussard flash` it needs)
- a parameter change shows or hides a com object (see [Change a parameter](change-a-parameter.md))
- the backup cannot be written
- there is no terminal and no `--yes`

"Verified" in the output means bussard read the tables and parameters back from the device and they match the model, not merely that the writes completed. The tables are rewritten whole, so running `apply` again after a failure is safe. `apply` also reminds you when no installation-wide [backup](back-up-and-replace.md) exists yet.

## Undo a change

bussard saves a copy of the model files before every command that writes the model or the bus. You do not need git.

```console
$ bussard status
2 pending change(s) since snapshot 20260922T101112Z-001 (2026-09-22T10:11:12Z):

Rocker 1 on Hallway push button (1.1.5) now switches Porch light (0/0/4).
Porch light (0/0/4) changes type from 1.001 to 1.002.

Nothing has reached any device yet. Run `bussard plan <ia>` to check a device,
`bussard apply <ia>` to write it, or `bussard undo` to put the files back.
$ bussard history
  1  20260922T100000Z-001  import home.knxproj (before writing the imported model)
     the first snapshot of the model
  2  20260922T101112Z-001  apply 1.1.5 → 192.0.2.10:3671 (before writing the device tables)
     Rocker 1 on Hallway push button (1.1.5) now switches Porch light (0/0/4) and 1 more
$ bussard undo
Restored the model files to snapshot 20260922T100000Z-001 (2026-09-22T10:00:00Z).
The state before this undo is kept as snapshot 20260922T103000Z-001.

Rocker 1 on Hallway push button (1.1.5) no longer switches Porch light (0/0/4).

Run `bussard plan 1.1.5` and `bussard apply 1.1.5` to push this to devices.
```

`undo` changes files only. The devices keep working as before until you run `plan` and `apply`. Without an argument it restores the newest snapshot that differs from your files; `bussard undo 1` picks one by number. The undo is snapshotted too, so you can undo it.

`bussard show 2` prints what one snapshot changed, `bussard show 1 2` the change between two, and `bussard status --raw` the file-level diff. An edit made in an editor is recorded by the next command as an `external edit` snapshot.

## See what the assistant changed

```console
$ bussard status
1 pending change(s) since snapshot 20260922T104500Z-001 (2026-09-22T10:45:00Z):

Living room blind actuator (1.1.4), channel B, now listens to Central down (3/0/1).
```

The assistant's edits go through the same history; `bussard history --json` shows which tool made each one. They reach a device only when pushed: by you with `plan` and `apply`, or by the assistant when its server runs with `--allow-programming`, each push after your yes to the plan. The assistant refuses a change to a `protected` group address outright. If you dislike a change, `bussard undo`. To run the server without edit tools, start it with `bussard mcp --no-model-edits`.

## Next steps

- [Change a parameter](change-a-parameter.md): run times, modes and other device settings.
- [Back up and replace](back-up-and-replace.md): a backup of every device before your first write.
- [Write commands](../explanation/write-commands.md): what each write command checks and refuses.
- [History commands reference](../reference/commands/history.md): `history`, `show` and `undo` in full.
