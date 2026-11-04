# Glossary

The words bussard uses when it talks to a person: CLI output, the
enrolment page, MCP tool results and summaries, and the user docs under
`docs/`. Code, file formats, protocol fields and maintainer docs keep their
technical names. Agreed with the owner on 2026-11-04 (#201 follow-ups).

The picture to keep in mind: a person has a **bussard project** (a folder of
files) that describes their **devices** and **group addresses**. bussard
compares it with what is on the **bus** and programs the devices from it.

## Terms

| Say | Meaning | Do not say to users |
|---|---|---|
| **project** | the folder bussard works on (`bussard.toml`, `groups.toml`, `devices/`, ...) | model, installation, model files |
| **in your project** / **not in your project** | a device or group address is described in those files | model known, model device, unknown to the model |
| **device** | a physical KNX device on the bus | node, member |
| **address** (`1.1.15`) | a device's individual address | IA, individual address (reference docs only) |
| **group address** (`1/2/3`) | as in ETS | GA (reference docs only) |
| **bus** | the KNX installation bussard reaches through the gateway | |
| **answered** / **did not answer** | a device replied, or not, within the timeout | responded, no response |
| **product** | what a device is: manufacturer, name, order number | application, catalog entry |
| **order number** | the manufacturer's part number, shown with the product | `Order` as a bare column name |
| **serial number** | a device's unique number, readable over the bus | |
| **certificate** | the KNX Secure sticker on a device, scanned or typed as its 36-character code | label, FDSK label |
| **factory key** | the key inside a certificate; reference docs add "(FDSK)" once | FDSK on its own |
| **key store** | `bussard.keys`, the project's encrypted keys | keyring (except an ETS `.knxkeys` file) |
| **Secure** / **secured** | KNX Secure is on for a device or group address | activated, Data Secure activated |
| **supports Secure** | a device could be secured but is not yet | Secure-capable |
| **session code** | the code the phone and bussard both show for one enrolment session | fingerprint (except in `dev/enroll-protocol.md`) |
| `bussard.lock` | named only when the file itself matters; otherwise "saved to your project" | "recorded in bussard.lock" |

## Certificate states

Shown the same way on the page, in the CLI and in MCP results. The protocol's
wire values (`dev/enroll-protocol.md`) do not change.

| Wire value | Badge | Detail line |
|---|---|---|
| `stored` | **added** | "for 1.1.3 Kitchen actuator" (address and device name) |
| `unassigned` | **no device yet** | "no device in your project has this serial number; bussard matches it once it finds the device (`bussard scan`)" |
| `already_stored` | **already known** | none, the badge says it |
| `conflict` | **conflict** | "your key store holds a different key for this device" |
| `invalid` | **invalid** | "check the code" |
| `error` | **failed** | the reason |

Summary on the phone: "6 sent · 1 added · 4 already known · 1 no device yet".
At the end: "Finished. You can close this page." then "Sent 6 certificates to
your bussard: 1 added, 5 already known."

## Showing certificates

- On the phone page a certificate is titled by its printed code, shortened to
  the first and last group (`AAFDHW … X4VCNL`), with the serial number below.
- In the terminal, MCP results and logs a certificate is shown only by its
  serial number and device, never by any part of its code or key: terminal
  output gets pasted into chats and logs.

## Style

- Plain words before KNX jargon; a KNX term the person meets in ETS (group
  address, line) is fine.
- Counts with the noun spelled out ("46 devices", "1 device"), not
  "device(s)".
- Concise, no em-dashes (`dev/docs-guide.md`).
