# Back up and replace

Keep a copy of what every device holds, put a device back to that copy, and swap a dead device for a new one. Take the backup before your first write to an installation.

## Back up every device

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

`backup` only reads, so it is safe on a live bus. Each device gets one JSON file with its link tables, the tables that say which group addresses each com object uses. `manifest.json` lists every device and what happened to it:

| Status | Meaning |
|---|---|
| `backed_up` | Tables, and where possible parameters, were saved. |
| `skipped` | bussard cannot read this mask (the device's system generation). |
| `unreachable` | Nothing answered at the address. |
| `failed` | The device answered but a read failed. The run exits 1. |

On System B devices the backup includes the parameters, with no product data needed. On System 7 it does not, because those devices do not report the size of their parameter memory.

Back up part of the installation with `--line 1.1` or a list of addresses, and write elsewhere with `--out <dir>`. Secure devices need `--keyring`.

Besides this, `apply` saves each device's tables to `captures/backups/` before it writes, and its parameters to `captures/backups/parameters/` when they change.

The assistant takes the same backup with `knx_backup_device`, for one device or all of them. It reads only.

## Restore a device's links

!!! warning
    `restore` writes the device's link tables. A gateway that is not on your own machine needs `--allow-remote-gateway`.

```console
$ bussard restore knx/captures/backups/20260922T101500Z 1.1.4
```

`restore` takes the newest backup of that device in the directory and runs it through `apply`: plan, confirmation, a fresh backup, write, read-back. A device that has not changed since the backup plans empty and nothing is written. `restore` writes link tables only; parameters in a table backup are reported, not written.

With `--allow-programming` the assistant does the same with `knx_restore_tables`, after your yes to the plan.

## Restore a parameter backup

!!! warning
    `restore --parameters` writes the device's parameter memory and restarts it.

```console
$ bussard restore --parameters knx/captures/backups/parameters/1.1.12-1790182579.json 1.1.12
```

This puts back the parameter memory saved before an earlier parameter write. It needs the product data the lock pins. It refuses before planning when the backup is of another device, another application or another mask. A device that does not run the application, such as a factory-fresh one, is refused and needs `bussard flash`.

Only the octets a parameter occupies are written; values the device manages itself keep their current state. The memory it overwrites is backed up first and the write is read back. The assistant does the same with `knx_restore_parameters`, after your yes to the plan.

## Replace a dead device

!!! warning
    `replace` assigns the address, flashes the application and writes the links on the device you press.

Mount a new device of the same product, connect it to the bus, and run:

```console
$ bussard replace 1.1.4 --product MDT_JAL_0410_02.knxprod
Press the programming button on the replacement device for 1.1.4.
device in programming mode: 15.15.255
  mask: 07B0 (System B)
  order number: MDT-JAL-0410.02
replace 1.1.4: address 15.15.255 → 1.1.4, flash the application and apply the model's tables, via 192.0.2.10:3671? [y/N] y
...
replaced 1.1.4 via 192.0.2.10:3671
```

After one confirmation `replace` assigns the old address, flashes the application with the model's parameters, writes the model's links, and records `replaced = <date>` in the device file. Without `--product` it uses the product data the lock pins. It refuses when:

- the old device still answers at the address
- the new device reports another order number or mask than the device file
- with `--no-flash`, the new device runs another application than the lock pins
- the pinned product data is missing or changed, before anything reaches the bus

`--force` overrides the first three, for a model that is out of date. Pass `--no-flash` for a spare that already carries the right application. If the flash or apply step fails, the address is already assigned, and the error names the command to run again.

## Clean stale links off a device

A link an old ETS download left on the device, but missing from its device file, shows in `bussard plan 1.1.5` as a `-` line: an address only the device has, which it `no longer uses` after the write.

`bussard apply 1.1.5` removes it, after the usual confirmation and backup. To see first what a device carries, `bussard reconstruct 1.1.5` reads its tables back and compares them with the model.

## Next steps

- [Change what a button does](change-a-link.md): plan, apply and undo.
- [Add a device](add-a-device.md): the first flash of a brand-new device.
- [Write commands](../explanation/write-commands.md): what `backup`, `restore` and `replace` check.
- [Programming commands reference](../reference/commands/programming.md): every flag.
