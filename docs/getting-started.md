# Getting started with bussard

`bussard` manages a KNX installation as code: your group addresses, links, and
devices live in YAML in a git repo, and the CLI reads that model to decode the
bus, read and write group values, and serve an MCP server for LLMs. This guide
takes you from an empty directory to a live, decoded bus.

## Install

Today, build and install from this repo with Cargo:

```console
$ cargo install --path crates/bussard-cli
$ bussard --version
```

Prebuilt binaries (Homebrew, winget, Scoop, `curl | sh`) are planned but not yet
published.

There are two ways in. Pick the one that matches what you have:

- **Path A — you have an ETS project.** Import it and you have a decoded bus in
  two commands.
- **Path B — no ETS project.** Start from an empty model and learn the bus by
  watching it.

## Path A: import an ETS project

If you have a `.knxproj` export from ETS, import it to populate the model:

```console
$ bussard import project.knxproj
```

This writes the model into `knx/` (override with `--dir`). Exports are usually
password-protected. Supply the password one of three ways, in order of
precedence: the `--password` flag, the `BUSSARD_PROJECT_PASSWORD` environment
variable, or an interactive prompt when neither is set.

```console
$ bussard import project.knxproj --password 's3cret'
$ BUSSARD_PROJECT_PASSWORD=s3cret bussard import project.knxproj
```

Check the model parsed cleanly:

```console
$ bussard validate
```

`validate` reports schema and semantic diagnostics (undefined GAs in links,
duplicate addresses, impossible com-object flags) in rustc-style text, or as
JSON with `--format json`.

Now watch the bus decode live against your model — the moment it clicks:

```console
$ bussard monitor
```

Every telegram resolves to its group-address name, the sending device, and a
typed value. Flip a switch and watch it name itself. Narrow the stream with
`--filter` (a comma-separated list of GAs like `3/2/0`, GA prefixes like `3/`,
or individual addresses like `1.1.30`).

## Path B: start from scratch

With no ETS project, initialise an empty model. `init` discovers your KNXnet/IP
gateway on the local network and writes the `knx/` skeleton:

```console
$ bussard init
```

If discovery finds nothing, KNX discovery is multicast and does not cross
subnets, so the usual cause is that this machine sits on a different subnet than
the gateway (the other is tunneling being disabled on the gateway). Find the
gateway's IP from your router or your Home Assistant KNX config and pass it
directly:

```console
$ bussard init --gateway 192.168.1.10        # tunnel to a specific gateway
$ bussard init --routing                     # KNXnet/IP routing (multicast)
```

`init` writes a valid skeleton either way — with a placeholder gateway you can
fill in later — so you can start watching the bus immediately:

```console
$ bussard monitor
```

At first the monitor shows raw GAs and hex, since the model is empty. Add
entries to `groups.yaml` as you identify them and re-run — decoding fills in as
your model grows. Automatic device discovery and model reconstruction
(`bussard scan`, `bussard import-product`) are coming in phase 2; see "Where
this is heading" below.

## Connect Claude via MCP

`bussard mcp` runs a read-only Model Context Protocol server over stdio, so
Claude can inspect your model and the live bus. Register it once:

```console
$ claude mcp add knx -- bussard mcp --dir knx
```

Then ask, in plain language:

- "What devices are on my bus?"
- "Watch for telegrams while I press the kitchen switch."
- "Read the wind speed."

The server is read-only by default and rate-limits bus reads. Pass `--passive`
to observe only — it drops the `knx_read_group` tool so the server never
transmits — or `--allow-writes` to register `knx_write_group` for value writes.
Even with writes enabled, any group address marked `protected: true` in
`groups.yaml` is hard-refused with no MCP override, so safety-critical objects
like a wind alarm can only be moved by a human running `bussard write … --force`
from the CLI.

## Where this is heading

The goal is to close the loop between a spoken intent and a reviewed change. Say
you add a presence detector and want it to trigger the hall light:

> "I added a Präsenzmelder in the Flur — it should switch the Flur light."

**Today**, bussard does the read-only half of that conversation. Claude can scan
recent telegrams to find the detector's group address (`knx_recent_telegrams`,
`knx_wait_for_telegram` for a "press it now" loop), read the current light state
(`knx_read_group`), and check the model (`knx_validate`) — the diagnosis and the
proposed YAML edit.

**Phase 2** makes it act: `bussard assign` to give a new device its individual
address ([#22](https://github.com/tmbo/bussard/issues/22)), `bussard
import-product` to generate a device model from its `.knxprod`
([#25](https://github.com/tmbo/bussard/issues/25)), and `bussard adopt` for the
guided new-device flow ([#26](https://github.com/tmbo/bussard/issues/26)). The
writes go through a Terraform-shaped `plan → apply`: the LLM edits YAML, you
approve a diff, the tool pushes it to the bus.

## What goes in git

The `knx/` directory is yours to version — `bussard.yaml`, `groups.yaml`,
`links.yaml`, and `devices/` are the source of truth and belong in the repo as
reviewable diffs.

Keep these out of git:

- `vendor/`, `models/` — vendor product data derived from `.knxprod` files;
  the application XML is the manufacturer's copyrighted work.
- `captures/` — local telegram captures (SQLite); `init` git-ignores this for
  you.
- `.env` — secrets like `BUSSARD_PROJECT_PASSWORD`.

## Home Assistant

Generate the Home Assistant KNX integration YAML from the same model, so your
KNX-as-code repo stays the single source of truth:

```console
$ bussard ha-config --out ha-knx.yaml
```

See [docs/ha-config.md](ha-config.md) for how entities are derived and how to
tune the result with `ha.yaml`.
