# Diagnostics

Every code `bussard validate` and the `knx_validate` MCP tool report, with its severity. For reading a validation report and deciding what to fix first.

`bussard validate` runs strict parsing first (see [Errors](files/errors.md)), then the rule passes below. `validate --json` prints `{"schema", "diagnostics": [...]}`.

## Model rules

| Code | Severity | Rule |
|---|---|---|
| E001 | warning | A link references a group address not defined in `groups.toml`. `import`, `apply` and the MCP edit tools declare it; `validate` alone warns. |
| E002 | error | A device file's name does not match its `address`. |
| E003 | error | A link references a communication object the device does not have. A warning when the device has no object table at all, because nothing can be checked without product data. |
| E004 | error | Conflicting object or DPT sizes on one group address, for the DPT main types whose size bussard models (the main number fixes the format, KNX 03_07_02 §1.1; an unmodelled main type is skipped, #498). |
| W005 | warning | Same size but different DPT main types on one group address (`5.001` against `6.010`). Subtypes of one main type agree (`1.001`, `1.005`, `1.019` on one 1-bit address is normal in ETS), as does a main type alone (`1`). |
| I006 | info | More than one sending object on a group address. Normal in KNX: two push buttons on one light, a central function next to a local one. Listed for review. |
| E007 | error | Impossible flags: no C flag, or `send` without T. |
| W008 | warning | A listening object with neither W nor U. |
| I009 | info | An orphaned object: T or W, never linked. |
| I010 | info | A group address defined but never linked. |
| W011 | warning | A group address without a DPT; `monitor` cannot decode it. |
| E012 | error | The reserved address `0/0/0` defined in `groups.toml`. |
| E013 | error | A link for a device that has no device file. |
| E014 | error | The same object linked more than once on one device. |
| I015 | info | A group address marked `protected = true`, listed so a reviewer sees the guarded set. |
| E016 | error | A parameter key is malformed (no `@`) or not in the product model. |
| E017 | error | A parameter value is invalid: unparseable, out of range, or not an enum member. |
| I017 | info | A parameter value equals the vendor default (redundant). |
| I018 | info | A device has parameters but no product model in `.bussard/models/` to validate against. |
| E020 | error | A duplicate group address in `groups.toml` (both lines), or a duplicate object in a device file. |
| E021 | error | A device has channels, parameters or keyed objects but no lock entry. |
| E022 | error | A device's `product` differs from its lock entry. |
| E023 | error | An unknown parameter or object key in a channel; the message lists the channel's keys. |
| E024 | error | An object linked to a group address whose main DPT number differs from the object's. |
| E025 | error | `send` on an object without the T flag, or `listen` on one without the W flag. Command objects `listen`, status objects `send`. |
| E026 | warning | Parameter values could not be checked because the product model is missing. The message names `bussard import-product` only when no stored archive carries the application; otherwise the model regenerates automatically. |
| E032 | warning | A device's lock entry names a product (`product_sha256`) the lock has no `[[product]]` entry for. |
| E033 | warning | A `[[product]]` entry names an archive (`file`) the model directory does not hold. The message names the recovery command for its origin. |

## `[knxnet]` rules

| Code | Severity | Rule |
|---|---|---|
| E043 | error | An IP interface's `[knxnet]` table contradicts itself: `assignment = "static"` without `address` or `netmask`; `address`, `netmask` or `gateway` under `dhcp`; or a `friendly_name` longer than 30 characters or outside ISO 8859-1. |
| E044 | error | A `[knxnet]` tunnel address is listed twice, or is the interface's own address. |
| E045 | error | A `[knxnet]` tunnel address is not on the interface's line. |
| E046 | error | A `[knxnet]` tunnel address is the address of a device in the model. |
| W047 | warning | The `[knxnet]` tunnel addresses of an IP interface differ from the tunnelling addresses the key store (or keyring) lists for it, its `Host` entries, which are the addresses `admit_tunnel_senders` admits on the Secure devices. The message names both lists. Runs with the key checks, and only for an interface the store lists tunnelling addresses for. |

## Key and KNX Secure rules

| Code | Severity | Rule |
|---|---|---|
| E027 | error | The configured keyring (`BUSSARD_KEYRING` or `connection.keyring`) points at a file that does not exist. |
| W028 | warning | A device file says `security.activated = true`, but there is no key store or keyring, the keyring is missing, or it has no tool key for the device. Re-export the keyring from ETS and `bussard keys import` it. |
| W029 | warning | A group's `secure` flag disagrees with the keyring: marked secure without a group key, or keyed in the keyring but not marked secure. |
| W030 | warning | The keyring does not read or decrypt; the key checks are skipped. |
| I031 | info | `BUSSARD_KEYRING_PASSWORD` is not set; the key checks are skipped. |
| W034 | warning | A secured group address (`secure = true`, keyed in the store) has no device sender, so only tunnel clients can write it, and a Secure device linked to it admits none of the store's tunnelling addresses: no `secure_senders` row lists one, and no keyring interface group entry covers the address. Set `admit_tunnel_senders = true` under `[connection]` and apply the device, or assign the address to a tunnelling connection in ETS. `knx_plan_device` adds the same sentence as a note for that device while the option is off. |
| E035 | error | A device without KNX Data Secure (no `secure_capable` in the lock) sends on a group address that a Secure receiver takes secured: its object is marked `secure`, or the address is. The receiver drops every plaintext telegram. The message names the sender, the address, the secured receivers and the two ways out: make the address plain, or send on a plain address into a logic input of the receiver. `knx_add_link` refuses such a link and `knx_plan_device` refuses to plan the sender. |
| E036 | error | The reverse of E035: a Secure device sends secured on a group address that a device without KNX Data Secure listens to, and that receiver cannot decrypt it. `knx_add_link` and `knx_plan_device` refuse it the same way. |
| W037 | warning | A Secure-capable device runs a secured group address but its security is not activated (ETS has not loaded its tool key), so it still sends and expects plain telegrams. The message says whether ETS has Secure commissioning set up for it. |
| E038 | error | Write time only: a secured write to a group address no device sends on (W034), whose Secure devices admit none of the tunnelling addresses, while `admit_tunnel_senders` is off. `bussard write` and `knx_write_group` refuse it before sending. |
| W039 | warning | A Secure-activated device sends on a secured group address, but `bussard.lock` records no `sequence_number` for it, so its receivers' sender tables (PID 54) can only be seeded from the keyring or with 0. |
| W040 | warning | A keyring export `bussard keys export` wrote is older than the key store's last change, or `[home_assistant]` is configured and no export is newer than that change (`bussard.keys.meta.toml`). |
| W041 | warning | A group address's `secure` flag and the `secure` flags of the Secure-capable objects linked to it disagree. The message names `bussard groups secure <ga> on\|off`, which sets the flag, the key store entry and the object flags together. |
| W042 | warning | Import time only: `bussard import` secures again a group address the model ran plain, or `bussard keys import` puts back the group key of one. It names the devices the next apply secures. |

`validate` runs E027 to I031 and W034 with `BUSSARD_KEYRING`, else the key store `bussard.keys`, else `connection.keyring`; the codes are the same for a store and an export. `knx_validate` runs them with the server's keyring. The rules see addresses only, never a key.

The Data Secure invariants split over these codes:

- every device on a secured address can run Data Secure (E035, E036), is activated (W037) and has its tool key in the key store (W028);
- the address's key is in the store (W029);
- a tunnel-only address admits the tunnel (W034, refused as E038 at write time);
- a Secure sender has a sequence source (W039);
- the group flag, the key store and the object flags agree (W029, W041);
- keyring consumers are not stale (W040);
- an import that secures a plain address again says so (W042).

W037, W039 and W041 read the model only; W040 reads `bussard.keys.meta.toml`.

## Lint rules

These rules are opt-in and run only when `bussard.toml` carries a `[lint]` table (see [bussard.toml](files/bussard-toml.md)):

| Code | Severity | Rule |
|---|---|---|
| L001 | warning | More devices on a line than `topology.max_devices_per_line`. |
| L002 | warning | A line's summed device bus current exceeds its `topology.supply_ma` budget. |
| L003 | warning | A device sits on a line `topology.supply_ma` does not declare. |
| L004 | warning | A KNX Secure device sits behind a line coupler that is not Secure-capable. |
| L005 | warning | A group address falls outside every block declared in `groups.blocks`. |
| L006 | warning | A command address has no feedback address on the offset its block reserves. |
| L007 | warning | A group address name does not match `groups.name_pattern`. |
| L008 | warning | A group address's DPT contradicts the role its block offset stands for. |

## Related

- [Errors](files/errors.md): the parse errors that come before these rules.
- [Model commands](commands/model.md): `bussard validate` and its flags.
- [bussard.toml](files/bussard-toml.md): the `[lint]` table and `admit_tunnel_senders`.
- [KNX Secure](../explanation/knx-secure.md): why the Secure rules exist.
