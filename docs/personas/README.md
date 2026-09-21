# Product personas

Internal reference for product decisions. Two people carry the weight of every
bussard feature: the owner who inherits a KNX house and the integrator who
builds one. This directory describes both, walks their journeys step by step,
maps each step to what bussard does today, and names the gaps. The gaps are
written up as ready-to-file issues in [issues.md](issues.md).

The personas are grounded in the KNX Association's project and handover
guidelines, ETS licence terms, integrator checklists, and several hundred forum
threads (knx-user-forum.de, openHAB and Home Assistant communities). Each
persona file ends with its sources.

| File | Persona | One-line summary |
|---|---|---|
| [homeowner.md](homeowner.md) | Nadia, the new owner | Gets the keys to a KNX house, wants to understand it, own it, and change it without paying for every button. |
| [integrator.md](integrator.md) | Jonas, the KNX integrator | Plans, addresses, commissions, documents and hands over KNX installations for customers, then lives with the change requests. |
| [issues.md](issues.md) | both | Seventeen issue drafts derived from the journey gaps, with acceptance criteria and labels. |

## How to use the personas

- A feature request should name the persona and the journey stage it serves.
  "Nadia, stage 3 (no project file)" is a complete justification; "would be
  nice" is not.
- When two designs conflict, the owner persona wins on safety and the
  integrator persona wins on throughput. Both are stated in DESIGN.md as the
  primary target (owners and small installations first) and the follow-on
  (larger installations later).
- The journey tables use three columns for bussard: "today" is what ships at
  HEAD, "gap" is what the persona still has to do by hand or with ETS, and the
  issue column points at the draft that closes the gap.

## What both personas share

Three facts shape both journeys and are worth keeping in mind for every
design decision.

The ETS project file is the single point of failure. It holds the names, the
room structure, the parameters and, for KNX Secure, the keys. Devices hold the
tables but none of the meaning. KNX's own guidelines oblige the outgoing
integrator to hand over the latest project, yet withholding it is common, and
without it the owner faces a two-to-three day reconstruction job or a rebuild
from scratch. bussard's YAML model in git is the answer to this problem, so
everything that gets the model populated, backed up and legible is on the
critical path.

ETS is Windows-only and priced for professionals. ETS6 Home is 350 EUR, caps at
64 devices and one project, and a normal single-family house often exceeds 64
devices. Professional is 1,000 EUR. Everything bussard can do without ETS is a
direct saving for the owner and a smaller licence dependency for the
integrator's customers.

The bus is shared and slow, and writes are physical. A tunnelling interface
has a fixed number of connections, often one to five, and Home Assistant, ETS
and bussard each need their own. A failed download leaves a device unloaded.
Both personas need plan-before-apply, verification and backups, and the
integrator additionally needs to do it sixty times in an afternoon.
