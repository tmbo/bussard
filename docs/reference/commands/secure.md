# KNX Secure commands

The commands that manage KNX Secure: the key store (`keys`), Data Secure on one group address (`groups secure`) and KNXnet/IP Secure on an IP interface (`interface secure`).

The key store, `bussard.keys` next to `bussard.lock`, is bussard's own copy of the key material, encrypted with the password in `BUSSARD_KEYRING_PASSWORD`. Its contents and format are on [the key store file](../files/bussard-keys.md); what "secured" means is explained in [KNX Secure](../../explanation/knx-secure.md).

## `bussard keys <VERB>`

Manage the key store: merge an ETS keyring export into it, write it out as one, or show what it holds.

```console
$ bussard keys import Projekt.knxkeys
devices: 1 added (1.1.13), 1 tool key(s) rotated (1.1.12), 8 unchanged
$ bussard keys export ha.knxkeys
$ bussard keys show
```

The output above is illustrative and abridged.

| Verb or flag | Default | Meaning |
|---|---|---|
| `import <FILE>` | | Merge this ETS `.knxkeys` export into the store, creating the store on first use. Its password must be the store's (`BUSSARD_KEYRING_PASSWORD`). |
| `export <FILE>` | | Write the store as a `.knxkeys` file ETS accepts. |
| `export --force` | off | Overwrite FILE if it exists. |
| `show` | | Print the summary of what the store holds. |
| `--json` | off | Print the result as JSON (below). |

What each verb does:

- **`import`** takes new devices, rotated tool keys, changed credentials, factory keys (FDSK) and group keys from the export. Entries the export lacks are kept, and a factory key is never dropped. The report lists what changed by address. Importing the same export twice changes nothing and writes nothing. `--json` prints `written`, `backup`, `changed` and the `report` object.
- **`export`** writes the ETS element and attribute set with a fresh `Created`, signed with the keyring key. A device without a tool key is left out and named.
- **`show`** prints the backbone, each device with its serial number and which keys it has, each interface with its user id and host, and the number of group keys. `--json` gives `project`, `created`, `has_backbone_key`, `devices[]` (`address`, `serial`, `has_tool_key`, `has_fdsk`, `has_management_password`, `has_authentication`), `interfaces[]` and `group_keys` (the addresses).

Behaviour:

- No key material or password is ever printed, in text or JSON.
- `export` refuses to overwrite an existing FILE unless `--force`.
- The store and every export it reads or writes share one password, `BUSSARD_KEYRING_PASSWORD`; there is no flag for it.
- Every bus command reads the store unless `--keyring` or `BUSSARD_KEYRING` names an explicit file (see [Global options](../global-options.md)). `validate` checks the model against it.
- `import` and `init` merge the one `.knxkeys` exported next to the project into the store when the password is set. Without it they print the `keys import` command to run.
- `keys import` warns when the export would secure a group address again that the model runs plain, naming the group address and the devices the next apply would secure.
- The model's `.gitignore` (from `init`) lists `*.knxkeys`, so an export dropped into the model directory is not committed by accident.

## `bussard groups secure <GA> on|off`

Switch KNX Data Secure on or off for one group address. bussard treats a group address as secured when the key store holds its group key, `groups.toml` marks it `secure`, or a linked com-object is `secure` in the lock, so the command changes all three.

```console
$ bussard groups secure 1/0/4 off
Licht Küche (1/0/4) now runs plain (KNX Data Secure off).
Aktor Küche (1.1.5): object 12 now runs plain (KNX Data Secure off).
The key store no longer holds a group key for 1/0/4.
The security object of 1.1.5 changes: run `bussard plan <ia>` and `bussard apply <ia>` for each to remove the group key table entry (PID 53) and the objects' security flags (PID 61).
Home Assistant and every other keyring user (ETS, a visualisation) still hold the group key of 1/0/4 ...
```

| Flag | Default | Meaning |
|---|---|---|
| `<GA>` | | The group address, e.g. `1/0/4`. |
| `on` or `off` | | Switch Data Secure on or off. |
| `--json` | off | Print `ga`, `secure`, `changes`, `group_key`, `devices`, `plan_devices`, `snapshot`, `snapshot_keeps_key_store` and `note`. |

What each direction does:

- **`off`** removes the group key from the key store (and the group address from every interface entry that lists it), and clears `secure` on the group and on every com-object linked to it on every device.
- **`on`** sets the flags and keeps the key the store has, or generates a new random 128-bit key, as ETS 6 does.

Behaviour:

- Files only: nothing reaches a device. Afterwards, `bussard plan` on each linked Secure device lists the security-object change, and `bussard apply` writes it (see [`plan`](programming.md)).
- `off` is refused while a linked object also links another secured group address: a group object's security flag covers all its group addresses.
- `on` is refused while a linked device is not Data Secure capable in the model.
- Needs `BUSSARD_KEYRING_PASSWORD` and the key store `bussard.keys`. A `BUSSARD_KEYRING` or `connection.keyring` that bus commands read instead gets a warning, since it keeps the old state.
- The history snapshot taken first keeps a copy of the encrypted key store, so one `bussard undo` restores the flags and the very key.
- Home Assistant, ETS and every other keyring user still hold the old key and keep sending the group address secured, which the device drops once it runs plain. Run `bussard keys export <file.knxkeys>` and load the new export there.
- An ETS re-import of a project that still marks the group address secure brings the flags back, and re-importing an old ETS keyring brings the key back. Change the group address in ETS too; `bussard import` and `bussard keys import` warn when this would happen.
- Over MCP the same switch is `knx_set_group` with `secure` (see [MCP tools](../mcp-tools.md)).

## `bussard interface secure on|off <ADDRESS>`

Switch KNXnet/IP Secure of a KNX IP interface on or off without ETS, with the sequence ETS sends. Credentials come from the key store and new ones go there; the device file never holds one.

```console
$ bussard interface secure on 1.1.200 --dry-run
$ bussard interface secure on 1.1.200
```

`--dry-run` prints the steps without a connection. The plan names any credential it would generate, never a value.

| Flag | Default | Meaning |
|---|---|---|
| `on` or `off` | | Switch KNXnet/IP Secure on or off. |
| `<ADDRESS>` | | The interface's individual address. |
| `--dry-run` | off | Print the steps; no connection, the key store unchanged. |
| `--dump-images <DIR>` | none | With `--dry-run`: write the steps' property writes to `DIR/plan.json` (`system: "ip-secure"`, key material as SHA-256 only) for offline comparison with an ETS capture. |
| `--yes` | off | Skip the confirmation prompt. |
| `--allow-self-reconfigure` | off | Switch the interface bussard tunnels through over a KNXnet/IP Secure session with that same interface. |
| `--json` | off | Emit `device`, `switch`, `dry_run`, `steps`, `generated`, `verified` and `mismatches`. |

!!! warning
    Both directions write the interface's security setup and end with a master reset, which restarts it.

Behaviour:

- `on` needs the device's factory key (FDSK) in the store. A tool key, device authentication code, management password or tunnelling user password the store lacks is generated and saved before the first write.
- `on` runs over a plain tunnel to a device in factory state, and is refused when the interface already reports secure-only tunnelling.
- `off` needs the tool key. Through a secure session with the interface itself it needs `--allow-self-reconfigure`.
- After the restart, the command reads the device back on a fresh connection under the key it should now hold, and checks the interface's secured service families. Through the interface itself, that connection is a KNXnet/IP Secure session with the store's credentials (`on`) or a plain tunnel (`off`).
- `off` drops the tool key from the store only once the device verified on its FDSK.
- Over MCP the same switch is `knx_interface_secure` (see [MCP tools](../mcp-tools.md)).

**Recovery.** If a switch stops half way, the device holds every step before the one named in the error, and the key store holds the credentials it was given and the FDSK. The previous store is `bussard.keys.bak`. Retry the command. If the device is unreachable with every credential the store holds, factory-reset it with its reset button: it returns to its FDSK and plain tunnelling, and `bussard interface secure on <ia>` sets it up again from the store. `bussard keys import` of an ETS keyring export restores the ETS credentials.

??? note "Details"
    `on`, under the FDSK: the security mode on (object type 17, PID 51) and the tool key (PID 56). Then under the tool key: the send sequence (PID 59), routing not secured, the device authentication code (type 11 PID 92), the password hashes of the management user and the tunnelling users (PID 93), device management secured, the tunnelling users (PID 97, `user id, address index` per `[knxnet] tunnels` slot; the index points into the interface's tunnelling addresses, PID 79, which the command reads first and which name the `[knxnet] tunnels` slots: a tunnel address that is not among them is refused, and an interface without PID 79 is taken to use the slots in order), tunnelling secured (PID 94), and a master reset.

    `off`, under the tool key: routing, device management and tunnelling not secured, the security mode off, the tool key back to the FDSK, a master reset. Then under the FDSK the three families again, and a master reset.

## `bussard secure diag <ADDRESS>`

Read a Data Secure device's security failures log, its security report and whether it broadcasts the report, with the device's tool key.

```console
$ bussard secure diag 1.1.5
$ bussard secure diag 1.1.5 --clear
```

| Flag | Default | Meaning |
|---|---|---|
| `<ADDRESS>` | | The device's individual address. |
| `--clear` | off | After a confirmation, clear the failures log and reset the security report, then read both back. |
| `--yes` | off | Skip the confirmation of `--clear`. |
| `--tool-key <HEX>` | none | A raw tool key for a test device; prefer `--keyring`. |
| `--json` | off | Emit `address`, `cleared` and `diagnostics` (`counters`, `latest`, `report_failure`, `report_broadcast`, `notes`). |

Over MCP the read is part of `knx_describe_device` and the clear is `knx_clear_security_log`, behind the same question (see [MCP tools](../mcp-tools.md)).

What it reads:

- the failure counters (PID 55): sequence number errors, cryptographic errors (a MAC that does not verify, a wrong or outdated key) and access errors (a group object's security flags that do not match the telegram);
- the latest failure: its sender, its sequence number and the error type;
- the security report (PID 57), set by the device on every failure until a tool resets it, and the report control (PID 58), which makes the device broadcast the report. `bussard monitor` names such a broadcast.

`--clear` fails unless the read-back after the clear finds every counter at 0 and the report clear. `bussard status <ADDRESS>` shows the same lines for a device read with its tool key, and over MCP `knx_describe_device` returns them as `security_diagnostics`.

## Related

- [Use KNX Secure](../../how-to/knx-secure.md): keyring, secure tunnelling and securing a group address, step by step.
- [The key store file](../files/bussard-keys.md): what `bussard.keys` holds.
- [KNX Secure explained](../../explanation/knx-secure.md): keys, secrets, and what secured means.
- [Programming commands](programming.md): `plan` and `apply`, which push a security change to devices.
