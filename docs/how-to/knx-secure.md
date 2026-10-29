# Work with KNX Secure

Bring the keys of a KNX Secure installation into bussard, connect through a secure interface, and switch security on or off for one group address or one IP interface. For owners whose integrator delivered an ETS keyring, and for integrators who secure installations.

A keyring (`.knxkeys`) is the encrypted file ETS exports with every Secure key of a project. bussard keeps its own copy in the key store, `bussard.keys` in the model directory.

## Set the keyring password

Put the password in the `.env` next to the model, and keep `.env` out of git:

```sh
BUSSARD_KEYRING_PASSWORD='the password of the ETS keyring'
```

One password serves the key store and every keyring bussard reads or writes. There is deliberately no flag for it, so it never lands in shell history. bussard never prints a key or a password, in text or JSON.

The key store is encrypted like the ETS keyring and meant to be committed with the model, so it is only as private as the password. Keyring exports stay out of git: `bussard init` lists `*.knxkeys` in `.gitignore`.

## Import an ETS keyring

```console
$ bussard keys import project.knxkeys
devices: 1 added (1.1.13), 1 tool key(s) rotated (1.1.12), 8 unchanged
```

The first import creates the store; later ones merge. New devices, rotated keys and changed credentials are taken from the export, entries it lacks are kept, and a factory key (FDSK, the key on the device's sticker) is never dropped. The keyring's password must be the store's. Importing the same keyring twice writes nothing.

`bussard import` and `bussard init` merge the one keyring exported next to the project automatically when the password is set. Each write keeps the previous store as `bussard.keys.bak`; copy it back to undo a bad import. `bussard keys show` lists what the store holds, without key material.

## Export a keyring for ETS or Home Assistant

```console
$ bussard keys export house.knxkeys
```

The file is a keyring ETS accepts, signed with the same password. A device without a tool key is left out and named. An existing file is refused unless you pass `--force`.

Home Assistant, ETS and a visualisation hold a copy of the keys. After the store changes, export again and load the new file there; `bussard validate` warns about a recorded export that is older than the last change.

## Connect through a KNXnet/IP Secure interface

An interface with secure-only tunnelling refuses a plain connection. With the key store in place there is nothing to add: bussard asks the interface whether it is secure, finds a tunnelling user for it in the store, and checks the interface's identity before it logs in. `--keyring <file.knxkeys>` or `BUSSARD_KEYRING` uses an ETS keyring instead of the store.

Without a keyring, name a tunnelling user and the variable that holds its password, for example:

```console
$ BUSSARD_TUNNEL_PW='...' bussard monitor --secure-user 2 --secure-password-env BUSSARD_TUNNEL_PW
```

The two flags go together, and the password is never a command-line argument. Without a keyring the interface's identity is not verified, and bussard warns.

- With no credentials at all, the command fails at once: `interface <gateway> requires KNXnet/IP Secure (secure tunnelling only) and no tunnelling credentials were given ...`.
- A refused password (`refused tunnelling user N`) is fatal.
- The session runs over TCP only, as the KNX standard requires. When the interface refuses the TCP connection, the message names the likely causes: secure tunnelling disabled, the interface's TCP connections all taken (often there is just one), or a different device at that address.

A device the keyring lists is managed over KNX Data Secure with its tool key; a plain device behind the secure interface stays reachable in the clear. A device the model marks Secure-activated but the keyring does not list is refused.

## Secure or unsecure one group address

```console
$ bussard groups secure 1/0/4 off
Licht Küche (1/0/4) now runs plain (KNX Data Secure off).
Aktor Küche (1.1.5): object 12 now runs plain (KNX Data Secure off).
The key store no longer holds a group key for 1/0/4.
...
```

This lets a non-Secure sender switch the address. It changes the key store, `groups.toml` and the lock in one snapshot, so `bussard undo` restores them, the key included. The devices change only when you run `bussard plan` and `bussard apply` on each linked device the output names.

- `off` is refused while a linked com object also links another secured group address.
- `on` keeps the store's key or generates a new one, as ETS does. It is refused while a linked device cannot run Data Secure.
- Re-export the keyring for Home Assistant and ETS: they still send the address secured, and the device drops that once it runs plain.
- Change the address in ETS too. A re-import of a project that still marks it secure brings the flags back, and an old keyring brings the key back; `bussard import` and `bussard keys import` warn when they do.

## Switch KNXnet/IP Secure of an IP interface

Preview the steps first; `--dry-run` opens no connection and leaves the store unchanged:

```console
$ bussard interface secure on 1.1.200 --dry-run
```

!!! warning
    `interface secure` writes the interface's security settings and ends with a master reset of the interface.

```console
$ bussard interface secure on 1.1.200
```

`on` runs over a plain tunnel to an interface in factory state and needs its FDSK in the key store. Any tool key, password or tunnelling user the store lacks is generated and saved before the first write. `on` is refused when the interface already reports secure-only tunnelling. `off` needs the tool key, and through a secure session with the same interface it also needs `--allow-self-reconfigure`. Each switch ends with a read-back on a fresh connection under the key the interface should now hold.

If a switch stops half way, retry the command. If the interface answers to no credential in the store, factory-reset it with its reset button: it returns to its FDSK and plain tunnelling, and `interface secure on` sets it up again. The previous store is in `bussard.keys.bak`.

## When a secured write does nothing

`bussard write` and `knx_write_group` report that the interface acknowledged a secured telegram. KNX reports nothing back from the devices, so a light that stays off needs a look at the receiving device:

```console
$ bussard secure diag 1.1.5
device 1.1.5 — KNX Data Secure diagnostics
  security failures (PID 55): 0 sequence, 0 cryptographic, 1 access
  latest failure: from 1.1.24: access error (a group object's security flags do not match the telegram, or a refused access)
  ...
```

Write again, then read the counters again:

- No counter moved: the device does not list the sender in its security individual address table (PID 54) and dropped the telegram without counting it. Set `admit_tunnel_senders = true` under `[connection]` and run `bussard plan` and `bussard apply` on the device.
- The cryptographic count went up: the device holds another group key for the address than the sender used. Re-import the current keyring and apply the device.
- The access count went up: a group object's security flags do not match the telegram's security (for example authentication only against authentication and encryption).

`bussard secure diag 1.1.5 --clear` resets the counters and the report after a confirmation, so the next write starts from zero. A device found on its factory key instead (it was reset to default) is named as such by every command; commission it again with ETS and import the new keyring.

## Next steps

- [KNX Secure explained](../explanation/knx-secure.md): what the key store holds and what secured means.
- [Secure commands](../reference/commands/secure.md): every flag of `keys`, `groups secure`, `interface secure` and `secure diag`.
- [Environment](../reference/environment.md): the `.env` file and the password variables.
