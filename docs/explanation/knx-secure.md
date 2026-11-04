# KNX Secure

KNX Secure protects your bus with keys, and bussard can only operate a
secured device while it holds that device's keys. This page explains what is
secured, where the keys live, and how to keep them safe.

## Two kinds of security

**KNX Data Secure** encrypts and authenticates telegrams end to end, device to
device. A device with Data Secure ignores plain management and plain telegrams
on its secured group addresses. bussard talks to it over Data Secure, with
keys from the key store.

**KNXnet/IP Secure** protects the link between bussard and the IP interface.
A secure-only interface accepts a tunnel only from a tunnelling user (a
user id and password the interface knows), and each of its connection slots
belongs to one user. With a keyring, bussard picks a user whose slot is free.

The two are independent. On a secure-only interface every command needs the
keyring, if only to open the tunnel. A device the keyring does not list is
then managed in the clear through the encrypted tunnel, as through a plain
interface.

## The keys a secured installation has

| Key | What it does |
|---|---|
| Tool key | the per-device key bussard and ETS use to manage a Data Secure device |
| FDSK | the factory key the device ships with, from its FDSK certificate; a factory reset returns the device to it |
| Group key | the key of one secured group address, shared by every device on it |
| Tunnelling user and password | opens a KNXnet/IP Secure tunnel |
| Device authentication code, management password | the IP interface's own credentials |
| Backbone key | secures routing on the IP backbone, which bussard does not implement |

## Activated means ETS has switched Data Secure on

A device is activated once ETS has turned Data Secure on and written its tool
key and sending sequence number. bussard operates activated devices but never
activates, re-keys or deactivates one; activation from the FDSK certificate
is not implemented. Keep those steps in ETS. KNXnet/IP Secure of an IP
interface is the exception: `bussard interface secure on|off` switches it
with the key store's credentials.

An activated device answers a plain identity read with mask `FFFF`. A device
whose model file says `security.activated: true` is never tried in the clear:
without a keyring entry the command refuses before anything is sent. A device
the model does not mark activated, but that is activated on the bus, refuses
the plain access, and the command tells you to export a current keyring from
ETS.

## The key store holds every key

`bussard.keys` in the model directory is bussard's own copy of the key
material: the backbone key, the tunnelling users and passwords, the
interfaces' authentication codes, every device's tool key, serial number,
FDSK, management password and authentication code, and the group keys. Anyone
who can decrypt it can manage every secured device and read and forge every
secured telegram.

- **It is encrypted and signed like an ETS `.knxkeys`**, with the password in
  `BUSSARD_KEYRING_PASSWORD`. Its protection is exactly the password's
  strength, so choose it accordingly. A wrong password or a hand edit fails
  the load rather than yielding wrong keys.
- **It is committed on purpose**, so `git checkout` restores the model and its
  keys together. A repository that holds it is only as private as the
  password.
- **The password is never a flag**, and bussard never writes it anywhere.
- **No key leaves in the clear.** `keys show`, `keys import` and their
  `--json` print addresses, counts and presence flags only, and logs redact
  every key.
- **Every write is atomic** and keeps the previous store as
  `bussard.keys.bak` until the next successful write. Copy the `.bak` back to
  undo a bad import; it uses the same password.
- **Sequence counters are not stored.** bussard seeds its send sequence from
  the clock, so restoring an old store never replays a sequence a device has
  already accepted.

`bussard keys import` writes the store, and so do `import` and `init`, which
merge the `.knxkeys` next to the project when the password is set. Every bus
command reads the store unless `--keyring` or `BUSSARD_KEYRING` names a file.
`connection.keyring` in `bussard.toml` is deprecated and ignored, with a
warning, when a store exists.

## A keyring export is a copy

A keyring export (`.knxkeys`) is the file ETS writes and Home Assistant or a
visualisation loads. `bussard keys export` writes one ETS accepts. Exports
are not committed: `init` lists `*.knxkeys` in the model's `.gitignore`.

Once the store changes, a consumer that loaded an older export encrypts with
keys the devices no longer use, or cannot read a newly secured address, and
nothing on the bus says why. bussard records the time of every store change
and every export in `bussard.keys.meta.toml` (paths and times only; commit it
with the store). `bussard validate` then warns about each export that still
exists and predates the last change, and, with `[home_assistant]` configured,
when no export is newer than that change. Re-export and load the file again;
the warning goes away.

After an address change of a Secure device, re-export from ETS too: the
keyring lists tool keys by individual address, and every later command looks
the key up under the new address.

## Certificate entry from a phone

Every Secure device ships with a certificate label that carries its factory
key (FDSK). `bussard keys enroll` takes these labels from a phone camera into
the key store, so you never type or paste one. The MCP tool
`knx_enroll_certificates` runs the same session for the assistant.

**How a label travels.** The phone reads the label, encrypts it on the phone
and sends it to a relay. The relay forwards it to your bussard, which
decrypts it, matches its serial number to a device and stores the key in the
encrypted key store. The phone then shows what became of each label.

| Party | Sees |
|---|---|
| bussard | the labels in plain text; it writes the key store |
| the page in the phone's browser | the labels it scans, on the phone only |
| the server that hosts the page | a request for a static page; the session details in the link never reach it |
| the relay | encrypted messages, a session id and their timing; it cannot decrypt them |
| the assistant and the chat | the link, the session code, serial numbers, addresses and statuses; never a label or a key |

**Scanning or typing.** Scanning is the safer way in. When you type a
code, the page turns off autocorrect, suggestions and autofill as far as
the browser allows, but some keyboards may still learn typed text.

**The link.** The page removes the session details from the address bar as
soon as it has read them, so the browser history and a synced browser never
hold them. A reload in the same tab still finds the session; a new tab needs
the link again. Before it asks for the camera, the page checks with the
relay that the session still exists.

**The session code.** bussard creates a fresh key pair for each session and
puts the public key in the link. bussard prints a session code derived from
it, and the page shows the code it derives from the key it received. Check
that both show the same code before you scan. A different code means the
link was changed on its way to the phone: close the page and start again.

**The hosted page and relay.** By default the link opens
`https://bussard.tmbo.dev/enroll/` and the messages pass through the hosted
relay. Neither keeps a label: bussard deletes the session when it ends, and
the relay forgets it after 30 minutes at the latest. `[enroll]` in
`bussard.toml` points both at your own copies.

**Local mode.** `bussard keys enroll --local` serves the page and the relay
from bussard itself on `127.0.0.1`. Open the link in a browser on the same
computer and scan with its camera or type the labels. Nothing leaves this
machine, and a phone cannot reach that address.

**At the end** bussard says how many labels it stored on a device, how many
wait for a device, and which were already known, in conflict or invalid,
and lists the next steps that apply. A label whose device the model does not
know yet waits under its serial number; `bussard scan` or `bussard adopt`
reads the serial off the device and attaches the key. After new keys,
`bussard keys export` gives ETS or Home Assistant a current keyring.

## Secrets and the .env file

bussard reads `BUSSARD_*` variables from one `.env` file: the first of
`<model dir>/.env`, the `.env` next to the model directory, and `./.env`.

- **The file stays out of git.** Keep `BUSSARD_KEYRING_PASSWORD`,
  `BUSSARD_PROJECT_PASSWORD` and `BUSSARD_HA_TOKEN` there only if `.env` is in
  `.gitignore`. `bussard export` never copies a `.env` into a bundle.
- **No value is printed.** `-vv` and `--timing` name the file and the keys it
  applied, never a value.
- **Only `BUSSARD_*` keys enter bussard**, so a `.env` shared with other tools
  does not leak their secrets into bussard's process.
- **An export beats the file**, even an empty one, so
  `BUSSARD_KEYRING_PASSWORD= bussard ...` runs without a password.
- **A `.env` never opens the write gate.** `BUSSARD_ALLOW_REAL_GATEWAY` in the
  file is ignored with a warning and dropped before anything reads it. A write
  to a real gateway still needs `--allow-remote-gateway` or an exported
  `BUSSARD_ALLOW_REAL_GATEWAY=1`. `BUSSARD_GATEWAY` from the file does select
  the gateway; reads go there, and writes to it stay gated.
- **`BUSSARD_NO_DOTENV=1`**, exported, skips the file for a hermetic run.

## Validation reports a broken secured link before a write

`bussard validate` checks the model's secured devices and group addresses
against the store, so a broken link shows up before a write rather than after
one. It reports when:

- a device on a secured group address cannot run Data Secure, is not
  activated, or has no tool key in the store;
- the address's key is missing from the store, or its `secure` flag, the store
  and the com-object flags disagree; the fix it names is
  `bussard groups secure <ga> on|off`;
- a Secure sender has no sequence number recorded;
- a secured address only tunnel clients write has devices that admit no
  tunnelling address. While `admit_tunnel_senders` is off, a write to it is
  refused: the devices would drop the telegram and the gateway's
  confirmation would hide that.

[Diagnostics](../reference/diagnostics.md) lists each code.

## Next steps

- [Use KNX Secure](../how-to/knx-secure.md): import a keyring, open a secure tunnel, secure a group address.
- [What each write command does](write-commands.md): secured downloads, sender admission and interface switching.
- [The key store file](../reference/files/bussard-keys.md): the file format and its companion files.
- [Environment](../reference/environment.md): every variable and the `.env` lookup.
