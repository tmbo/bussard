# KNX handover checklist

Attach this page to a purchase contract or an acceptance protocol. The owner uses it as the list of what to demand; the integrator uses it as the delivery list. It follows the handover and security checklists in the KNX Association's [KNX Project Preparation](https://www.knx.es/_data/docsfiles/5_KNX-Project-Preparation_en.pdf).

Installation: ______________________  Integrator: ______________________  Date: __________

## Project data

- [ ] Latest ETS project (`.knxproj`), exported on: __________
- [ ] Project password (or: sealed envelope, see below)
- [ ] KNX Secure keyring (`.knxkeys`) and its password
- [ ] FDSK stickers or their list, one per Secure device
- [ ] BCU key, if one is set on any device (or: "no BCU key set")
- [ ] What changed since the last delivered version, with dates

## Access

- [ ] Gateway or interface: IP address, individual address, web login
- [ ] Tunnelling addresses in use, and which client holds each (visualisation, Home Assistant, spare)
- [ ] IP Secure: device password and commissioning password per interface
- [ ] Visualisation and remote access: URLs, users, passwords
- [ ] Default passwords changed on every interface and server

## Documentation

- [ ] Device list: individual address, name, room, manufacturer, order number
- [ ] Group address list with names and data types (DPTs)
- [ ] As-built plans: distribution board, line topology, device locations
- [ ] Description of logic functions, scenes, timers and central functions
- [ ] Which group addresses carry safety functions (wind, rain, frost, central off)
- [ ] Device manuals or links to them
- [ ] Acceptance report: functional test per room, signed by both sides

## For a bussard-managed installation

- [ ] Handover bundle (`bussard export`), file name: ______________________
- [ ] Model checksum (`model_sha256` from the bundle manifest):
      ________________________________________________________________
- [ ] House manual from `bussard doc`
- [ ] Acceptance test report from `bussard test`, with the `tests.yaml` it ran
- [ ] Backup from `bussard backup`, taken after the last `apply`

The bundle and its checksum are the delivered state. `bussard diff` against this bundle shows, in sentences, anything changed since.

## Who owns the project file

The KNX Project Design Guidelines say the integrator "is obliged to hand over the very latest version of the project data", and the Swiss KNX guidelines of 2024 say it must be handed over. Guidelines are not law: the contract decides, and court rulings point both ways. Put the handover of the project data and its passwords into the contract. An integrator who worries about warranty can hand over a password-protected project with the password in a sealed envelope; an opened envelope then marks the point where the owner took over.

Received complete: ______________________ (owner)  Delivered: ______________________ (integrator)
