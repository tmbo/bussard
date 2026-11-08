# Back up and replace

Keep a copy of what every device holds, put a device back to that copy, and swap a dead device for a new one. Take the backup before your first write to an installation.

## Back up every device

=== "In chat"

    ```text
    You:        Back up every device.
    Assistant:  (calls knx_backup_device with all: true)
                10 of 12 devices backed up into captures/backups/. One
                System 1 device cannot be read, and one did not answer.
    ```

    `knx_backup_device` backs up one device or all of them. The default server may run it; a `--passive` server does not offer it.

=== "At the terminal"

    ```console
    $ bussard backup
    backing up 12 device(s) via 192.0.2.10:3671 into knx/captures/backups/20260922T101500Z
    ...
      1.1.4      07B0  backed up
          parameters: 1840 octet(s)
      1.1.12     0010  skipped
          unsupported mask 0010 (System 1): ...

    10 backed up, 1 skipped, 1 unreachable, 0 failed
    ```

    Back up part of the installation with `--line 1.1` or a list of addresses, and write elsewhere with `--out <dir>`. Secure devices need `--keyring`.

The backup only reads, so it is safe on a live bus. Each device gets one JSON file with its link tables, the tables that say which group addresses each com object uses. `manifest.json` lists every device and what happened to it:

| Status | Meaning |
|---|---|
| `backed_up` | Tables, and where possible parameters, were saved. |
| `skipped` | bussard cannot read this mask (the device's system generation). |
| `unreachable` | Nothing answered at the address. |
| `failed` | The device answered but a read failed. The terminal run exits 1. |

On System B devices the backup includes the parameters, with no product data needed. On System 7 it does not, because those devices do not report the size of their parameter memory.

Besides this, every write saves the device's tables to `captures/backups/` first, and its parameters to `captures/backups/parameters/` when they change.

## Restore a device's links

!!! warning
    A restore writes the device's link tables. A gateway that is not on your own machine needs `--allow-remote-gateway`.

=== "In chat"

    ```text
    You:        Put 1.1.4 back the way it was in this morning's backup.
    Assistant:  (calls knx_restore_tables)
                Restoring adds 2 links and removes 1 on the Jung
                actuator. Nothing is written yet. Restore it?
    You:        Yes.
    Assistant:  (calls knx_restore_tables with the plan's digest)
                Restored and verified: the tables match the backup.
    ```

    `knx_restore_tables` needs a server started with `--allow-programming`. Without a named backup it takes the newest one an earlier write kept of the device.

=== "At the terminal"

    ```console
    $ bussard restore knx/captures/backups/20260922T101500Z 1.1.4
    ```

    `restore` takes the newest backup of that device in the directory and runs it through `apply`.

Either way the restore is a plan, your yes, a fresh backup, the write and a read-back. A device that has not changed since the backup plans empty and nothing is written. Only link tables are written; parameters in a table backup are reported, not written.

## Restore a parameter backup

!!! warning
    A parameter restore writes the device's parameter memory and restarts it.

=== "In chat"

    ```text
    You:        Put the heating actuator's old parameters back.
    Assistant:  (calls knx_restore_parameters)
                Night setback goes back from 17 °C to 18 °C. Restore it?
    You:        Yes.
    Assistant:  (calls knx_restore_parameters with the plan's digest)
                Restored and verified.
    ```

    `knx_restore_parameters` needs a server started with `--allow-programming` and the backup's file name under `captures/backups/parameters/`.

=== "At the terminal"

    ```console
    $ bussard restore --parameters knx/captures/backups/parameters/1.1.12-1790182579.json 1.1.12
    ```

This puts back the parameter memory saved before an earlier parameter write. It needs the product data the lock pins. It refuses before planning when the backup is of another device, another application or another mask. A device that does not run the application, such as a factory-fresh one, is refused: it needs its application loaded first ([Add a device](add-a-device.md#flash-a-factory-fresh-device)).

Only the octets a parameter occupies are written; values the device manages itself keep their current state. The memory it overwrites is backed up first and the write is read back.

## Replace a dead device

!!! warning
    Replacing assigns the address, loads the application and writes the links on the device you press.

Mount a new device of the same product and connect it to the bus.

=== "In chat"

    An illustrative exchange:

    ```text
    You:        The blind actuator in the living room is dead. I mounted
                a new one of the same type.
    Assistant:  (calls knx_replace_device)
                I kept a backup of its device file. Press the programming
                button on the new device, then say done.
    You:        Done.
    Assistant:  (calls knx_job_status)
                It is an MDT JAL-0410.02 at 15.15.255, the same product.
                I would give it 1.1.4, load its application and write
                the parameters and links from your project. Go ahead?
    You:        Yes.
    Assistant:  (calls knx_replace_device with yes, then knx_job_status)
                Replaced and verified: 1.1.4 matches your project again.
    ```

    `knx_replace_device` needs a server started with `--allow-programming`. One yes covers the address, the application and the links, and the replacement is recorded only after a verified write. A device your project records as secured is refused, because securing its replacement needs ETS.

=== "At the terminal"

    ```console
    $ bussard replace 1.1.4 --product MDT_JAL_0410_02.knxprod
    Press the programming button on the replacement device for 1.1.4.
    device in programming mode: 15.15.255
      mask: 07B0 (System B)
      order number: MDT-JAL-0410.02
    replace 1.1.4: address 15.15.255 → 1.1.4, flash the application and apply the tables in your project, via 192.0.2.10:3671? [y/N] y
    ...
    replaced 1.1.4 via 192.0.2.10:3671
    ```

    Without `--product` it uses the product data the lock pins. `--force` overrides the first three refusals below, for a project that is out of date. Pass `--no-flash` for a spare that already carries the right application.

After one confirmation bussard assigns the old address, loads the application with your project's parameters, writes your project's links, and records the replacement in the device file. It refuses when:

- the old device still answers at the address
- the new device reports another order number or mask than the device file
- with `--no-flash`, the new device runs another application than the lock pins
- the pinned product data is missing or changed, before anything reaches the bus

If the flash or the write fails, the address is already assigned, and the error names what to run again.

## Clean stale links off a device

A link an old ETS download left on the device, but missing from its device file, shows in the plan as an address only the device has, which it `no longer uses` after the write (a `-` line in `bussard plan 1.1.5`).

=== "In chat"

    Ask the assistant to plan the device (`knx_plan_device`) and say yes to the write (`knx_apply_device`). To see first what a device carries, `knx_reconstruct_device` reads its tables back against your project.

=== "At the terminal"

    `bussard apply 1.1.5` removes it, after the usual confirmation and backup. To see first what a device carries, `bussard reconstruct 1.1.5` reads its tables back and compares them with your project.

## Next steps

- [Change what a button does](change-a-link.md): plan, apply and undo.
- [Add a device](add-a-device.md): the first flash of a brand-new device.
- [Write commands](../explanation/write-commands.md): what `backup`, `restore` and `replace` check.
- [Programming commands reference](../reference/commands/programming.md): every flag.
