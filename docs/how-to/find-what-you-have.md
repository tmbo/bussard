# Find what you have

Find out what the model holds, which devices answer on the bus, and what bussard can do with each of them. Every command here reads; none of them changes a device.

## Audit the installation

```console
$ bussard audit
== Model ==
project: my-house   imported from: my-house.knxproj
38 device(s), 214 group address(es), 402 link(s)
  line 1.1: 38 device(s)
...
== Devices per mask ==
  07B0 System B (29 device(s)): bussard can: plan/apply, flash, reconstruct, describe
  0705 System 7 (7 device(s)): bussard can: plan/apply, flash, reconstruct, describe
  0012 System 1 (2 device(s)): bussard can: describe only
```

The first section is the project summary: name, import source, and the count of devices, group addresses and links per line. Below it `audit` lists what needs attention:

- devices without a name or a location
- group addresses without a type (DPT) or a name
- links to com objects the device file does not declare
- one-sided links: a group address with senders but no listener, or the reverse
- protected group addresses and KNX Secure devices

"Devices per mask" groups devices by their mask, the device's system generation, and says what bussard can do with each. A device marked `describe only` cannot be programmed by bussard.

Unlinked com objects and unused group addresses are counted, not flagged. Actuators ship far more objects than a house uses, and an unused group address is a reserve.

Add `--keyring <file.knxkeys>` (password in `BUSSARD_KEYRING_PASSWORD`) to see which Secure devices your keyring covers. `--json` prints the same report as one object; the assistant gets it from `knx_audit`, and `knx_project_summary` gives it the counts and the bus status.

## Check the live bus

```console
$ bussard audit --live
```

`--live` adds three things: the gateway's tunnel budget, a traffic sample over `--window` seconds (default 30), and a probe of every modelled device, one at a time. It sends only management reads to single devices, never a group telegram, so no light switches.

## See which devices are on a line

```console
$ bussard scan 1.1
IA         MASK    SYSTEM     MANUFACTURER    ORDER             MODEL
1.1.1      07B0    System B   MDT             BE-06001.02       known
1.1.4      07B0    System B   Albrecht Jung   23024 1S R        known
1.1.47     07B0    System B   MDT             JAL-0810.03       NOT in model

3 device(s) responded
1 not in model
all model devices on this line responded
```

The summary is the point: which devices the model knows, which are unexpected, and which model devices did not answer. `scan` probes one address at a time, because most gateways handle one device session at a time, so a full line can take a while. Narrow it with `--from` and `--to` (device numbers 0 to 255). The line defaults to `1.1`.

## Look inside one device

```console
$ bussard describe 1.1.4
```

`describe` lists the device's interface objects and every property it reports, with type, size and access level. Use it on an unknown device during commissioning. It never writes. A Secure device needs its tool key: pass `--keyring`. A Secure device that answers only under its factory key (FDSK) from the key store was reset or never commissioned; `describe` says so, and you commission it with ETS and import the new keyring.

```console
$ bussard reconstruct 1.1.4
```

`reconstruct` reads the device's link tables back and compares them with the model, group addresses per com object. It cannot tell send from listen, because many devices do not expose that. Give it `--product <file.knxprod>`, or let it use the product data the lock pins, and it also decodes the parameters that differ from the vendor default and from the model. It refuses a device whose mask it cannot read; `audit` shows which devices allow `reconstruct`.

To build a new model from what a whole line carries, see [Add a device](add-a-device.md).

## Check one device's identity

```console
$ bussard status 1.1.250
```

With an address, `status` reads the device's mask and identity and compares them with the lock. For a KNX IP interface it also prints its IP settings, tunnelling addresses and state, and each difference from the device file. Without an address, `status` shows the model changes not yet written to any device (see [Change what a button does](change-a-link.md)).

## Get past "no free tunnelling connection"

```
error: 192.0.2.10:3671 has no free tunnelling connection (E_NO_MORE_CONNECTIONS).
```

Your IP interface has a fixed number of tunnelling slots, often one to five. A tunnelling slot is one client connection; each connected program holds one for as long as it runs:

- Home Assistant's KNX integration, permanently
- ETS, while a project is online
- `bussard viz`, `bussard mcp`, or any other bussard command still running

When all are taken, bussard says so and exits with code `4` instead of timing out. Retrying does not help until a slot is free. Stop one of the other clients, or wait about two minutes for a crashed client's slot to time out. A long-running observer can use routing (`--routing`) instead, if your interface supports multicast. `bussard init --gateway <ip>` and `bussard audit --live` print `N tunnels, M in use` when the interface reports it.

A bussard write never retries into a full interface, so the refusal comes before anything reaches a device.

## Next steps

- [Watch the bus](watch-the-bus.md): decode live traffic and name what you see.
- [Device support](../explanation/device-support.md): which masks bussard programs, and the tunnel budget in detail.
- [Device commands reference](../reference/commands/devices.md): every flag of `scan`, `describe`, `reconstruct` and `status`.
