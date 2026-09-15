# Getting started with bussard

This guide takes you from an empty directory to a live, decoded KNX bus, then connects
Claude to it over MCP. It covers install, the two ways to build a model (import an ETS
project, or start from scratch), reading and writing group values, and safety.

## Install

Build and install from this repo with Cargo:

```console
$ cargo install --path crates/bussard-cli
$ bussard --version
```

Prebuilt binaries (Homebrew, winget, Scoop, `curl | sh`) are planned but not yet
published.

## Three KNX terms

The model and every command use three KNX concepts:

- **Group address (GA)**, written `3/2/0`. The bus's pub/sub topic: a telegram sent to a
  GA carries one value (light on, blind down, 21.4 °C) and every device listening on that
  GA reacts. `groups.yaml` names each GA and records its datapoint type (DPT), which
  tells bussard how to decode the value.
- **Individual address (IA)**, written `1.1.4` (area.line.device). A device's unique bus
  address, used for commissioning and diagnosis. Runtime traffic goes to GAs; the IA
  mainly appears as the sender of a telegram. Each `devices/*.yaml` file is keyed by its
  device's IA.
- **Com object**: one input or output slot of a device, such as "channel A: move up/down"
  on a blind actuator. Linking a com object to a GA (in `links.yaml`) makes the device
  send on or listen to that address. A compact flag string (`CRWTUI`) records what the
  object may do; the two that matter here are W (accepts writes, a command input) and T
  (transmits, a status output).

## Path A: import an ETS project

With a `.knxproj` export from ETS, two commands get you a decoded bus. Import it first:

```console
$ bussard import home.knxproj
imported 421 group addresses, 46 devices, 531 link entries → knx
```

This writes the model into `knx/` (override with `--dir`). Exports are usually
password-protected. Supply the password one of three ways, in order of precedence: the
`--password` flag, the `BUSSARD_PROJECT_PASSWORD` environment variable, or an interactive
prompt when neither is set.

```console
$ bussard import home.knxproj --password 's3cret'
$ BUSSARD_PROJECT_PASSWORD=s3cret bussard import home.knxproj
```

Check the model parsed cleanly:

```console
$ bussard validate
info[I009]: com object 534 on 1.1.3 has T/W flags but is not linked
  --> devices/1.1.3-heating-actuator-6-gang-with-controller.yaml com_objects.534
info[I010]: GA 4/4/6 is defined but never linked
  --> groups."4/4/6"

0 errors, 51 warnings
```

`validate` reports schema and semantic diagnostics (undefined GAs in links, duplicate
addresses, impossible com-object flags) in rustc-style text, or as JSON with
`--format json`. Infos like the ones above are normal after an import.

Now watch the bus decode live against your model:

```console
$ bussard monitor
12:03:41.221  1.1.30 Meteodata          → 3/2/0 Windalarm            = Alarm (1.005, obj "Windalarm 1")
12:03:44.809  1.1.12 Taster Flur EG     → 1/0/1 Licht Flur           = On (1.001, obj "Taste 1")
12:03:44.981  1.1.7 Schaltaktor UV      → 1/0/2 Licht Flur Status    = On (1.001)
```

Every telegram resolves to its group-address name, the sending device, and a typed value.
Flip a switch and watch it name itself. Narrow the stream with `--filter`, a
comma-separated list of GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`), or individual
addresses (`1.1.30`). `--json` emits one JSON object per line for tooling.

## Path B: start from scratch

Without an ETS project, initialise an empty model. `init` discovers your KNXnet/IP
gateway on the local network and writes the `knx/` skeleton:

```console
$ bussard init
Searching for KNXnet/IP gateways on the local network...
Found gateway: KNX IP Interface (192.168.1.74:3671, IA 1.1.250)

Created a fresh KNX model in knx.

Next steps:
  - Watch the bus:            bussard monitor --dir knx
  - Import an ETS export:     bussard import project.knxproj --dir knx
  - Connect Claude via MCP:   claude mcp add knx -- bussard mcp --dir knx

Check the model any time:     bussard validate --dir knx
```

If discovery finds nothing, the usual cause is that this machine sits on a different
subnet than the gateway (KNX discovery is multicast and does not cross subnets); the
other is tunneling being disabled on the gateway. Find the gateway's IP from your router
or your Home Assistant KNX config and pass it directly:

```console
$ bussard init --gateway 192.168.1.10        # tunnel to a specific gateway
$ bussard init --routing                     # KNXnet/IP routing (multicast)
```

`init` writes a valid skeleton either way, with a placeholder gateway you can fill in
later, so you can start watching the bus immediately. At first the monitor shows raw GAs
and hex, since the model is empty. Add entries to `groups.yaml` as you identify them and
re-run; decoding fills in as your model grows.

To see which devices are physically on a line, scan it. The scan sweeps addresses one at
a time (most gateways cannot multiplex connection-oriented sessions), so a full line
takes a while:

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

With a model present, the delta is the point: which devices are known, which are
unexpected, and which model devices did not answer. `--json` emits the same report for
tooling.

## Read and write group values

`read` sends a GroupValueRead and prints the typed response (non-zero exit on timeout,
so scripts can detect a non-responding object):

```console
$ bussard read 4/1/11
4/1/11 Außen Temperatur
21.4 °C (9.001)
```

`write` encodes a human value against the GA's DPT from `groups.yaml` (or `--dpt`) and
sends a GroupValueWrite. Accepted values include `on`/`off`, `up`/`down`, numbers, and
percentages like `75%`:

```console
$ bussard write 3/0/4 down
3/0/4 Jalousie Wohnen Süd — Auf/Ab ← Down (1.008)
```

A GA marked `protected: true` in `groups.yaml` (a wind alarm, a central function) is
refused unless a human explicitly forces it:

```console
$ bussard write 3/2/0 off
error: refusing to write to protected GA 3/2/0 ("Windalarm"); pass --force to override
```

## Connect Claude via MCP

`bussard mcp` runs a Model Context Protocol server over stdio, so Claude can inspect
your model and the live bus. Register it once:

```console
$ claude mcp add knx -- bussard mcp --dir knx
```

Then ask, in plain language:

- "What devices are on my bus?"
- "Watch for telegrams while I press the kitchen switch."
- "Read the wind speed."

The server has three access tiers:

| Tier | Flag | On the bus |
|---|---|---|
| Passive | `--passive` | Never transmits. Drops the `knx_read_group` tool. |
| Read (default) | none | May send GroupValueReads, rate-limited. |
| Write | `--allow-writes` | Adds `knx_write_group` for group value writes. |

Even with writes enabled, a GA marked `protected: true` is hard-refused with no MCP
override. That stance is deliberate: the LLM must ask a human, who can then run
`bussard write … --force` from the CLI. Pass `--capture-db captures/bus.db` to extend
the telegram history tools beyond the in-memory window using a `bussard capture`
database.

## Where this is heading

The goal is to close the loop between a spoken intent and a reviewed change. Say you add
a presence detector and want it to trigger the hall light:

> "I added a Präsenzmelder in the Flur, it should switch the Flur light."

Today, bussard does the diagnosis half of that conversation. Claude can scan recent
telegrams to find the detector's group address (`knx_recent_telegrams`, and
`knx_wait_for_telegram` for a "press it now" loop), read the current light state
(`knx_read_group`), check the model (`knx_validate`), and propose the YAML edit. On the
CLI, `bussard scan` finds the device on the line and `bussard import-product` generates
its com-object and parameter model from the vendor `.knxprod` (see
[product-data.md](product-data.md)).

Commissioning helpers exist too: `bussard assign` gives the device in programming mode
its individual address (explicit, or the next free one on the line), and
`bussard reconstruct 1.1.4` reads a System B device's group-address and association
tables back over the bus and diffs them against `links.yaml`. Still open:
`bussard adopt`, the guided new-device flow
([#26](https://github.com/tmbo/bussard/issues/26)), and the configuration downloader.
Device writes will go through a Terraform-shaped `plan → apply`: the LLM edits YAML, you
approve a diff, the tool pushes it to the bus.

## What goes in git

The `knx/` directory is yours to version. `bussard.yaml`, `groups.yaml`, `links.yaml`,
and `devices/` are the source of truth and belong in the repo as reviewable diffs. Which
fields survive a re-import is documented in
[DESIGN.md](DESIGN.md#52-the-yaml-model-the-users-knx-as-code-repo).

Keep these out of git:

- `vendor/`, `models/`: vendor product data derived from `.knxprod` files. The
  application XML is the manufacturer's copyrighted work; `import-product` plants a
  `.gitignore` for you.
- `captures/`: local telegram captures (SQLite); `init` git-ignores this for you.
- `.env`: secrets like `BUSSARD_PROJECT_PASSWORD`.

## Home Assistant

Generate the Home Assistant KNX integration YAML from the same model, so your
KNX-as-code repo stays the single source of truth:

```console
$ bussard ha-config --out ha-knx.yaml
```

See [ha-config.md](ha-config.md) for how entities are derived and how to tune the
result with `ha.yaml`.
