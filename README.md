# bussard

An open-source, cross-platform CLI for KNX. No GUI, ever.

`bussard` (German for buzzard, a bird that watches the field from above; the name also
contains "bus") aims to replace ETS for day-to-day work on an existing KNX installation:

- **Configuration as code.** Group addresses, links, and device parameters live in YAML
  files in a git repo, so changes are reviewable diffs and an LLM can propose them safely.
- **Terraform-shaped workflow.** `import → validate → plan → apply`: bootstrap the model
  from an existing ETS project, check it, preview a change, push it to the devices over
  the bus.
- **Bus observation.** Live monitor, telegram capture, and decoding against the same YAML
  model, plus an MCP server so LLMs can debug the installation.

```
.knxproj (ETS export)      .knxprod (vendor data)
      │ import                   │ import-product
      ▼                          ▼
 ┌──────────────────────────────────────┐
 │  YAML model in git (knx/)            │──▶ validate · ha-config
 └──────────────────┬───────────────────┘
                    │ decode / encode
     monitor · capture · read · write · mcp
                    │
         KNXnet/IP gateway ↔ KNX bus
```

**Status: early development.** The read-only workflow (import, validate, monitor,
capture, MCP), runtime writes (read, write, ha-config), and the commissioning helpers
(scan, assign, reconstruct, import-product) work today. The device downloader (the
plan/apply half) is not built yet. See
[docs/getting-started.md](docs/getting-started.md) and the
[milestones](https://github.com/tmbo/bussard/milestones).

## Design goals

- Easy and quick to install: a single static binary (Homebrew / winget / Scoop /
  `curl | sh`), no runtime.
- Primary target: home owners and small installations.
- Speed everywhere: sub-second to first frame, pipelined multi-device operations,
  differential downloads.
- All configuration is file based.
- Fail fast and fail gracefully; never leave the KNX system in an inconsistent state.

Non-goals: replacing ETS for certification, planning, or documentation; supporting every
KNX device ever made; any graphical interface.

## Getting started

Build and install from this repo (prebuilt binaries are planned):

```
cargo install --path crates/bussard-cli
```

Two ways in. With an ETS project, `bussard import project.knxproj` populates the model,
then `bussard validate` and `bussard monitor` give you a live, decoded bus. Without one,
`bussard init` discovers your gateway and writes an empty model to watch with
`bussard monitor`.

See [docs/getting-started.md](docs/getting-started.md) for the full walkthrough,
including the MCP setup for LLM-assisted debugging.

## CLI surface

Every command below works today.

```
bussard init                            # discover the gateway, write an empty model
bussard import project.knxproj          # bootstrap YAML from an existing ETS project
bussard validate [--format json]        # schema + semantic checks on the YAML
bussard monitor [--filter EXPR]         # live bus, decoded against the model
bussard capture --to bus.db             # persistent telegram store (SQLite)
bussard read 3/2/0                      # group value read
bussard write 3/0/4 down [--force]      # group value write
bussard scan 1.1                        # find devices on a line, diff against the model
bussard assign [1.1.47]                 # address the device in programming mode
bussard reconstruct 1.1.4               # read device tables back, diff vs the model
bussard import-product dev.knxprod      # cache vendor data, generate a device model
bussard ha-config [--out FILE]          # generate the Home Assistant KNX config
bussard mcp [--passive|--allow-writes]  # serve MCP over stdio
```

## Documentation

- [docs/getting-started.md](docs/getting-started.md): install, import, monitor, MCP. Start here.
- [docs/DESIGN.md](docs/DESIGN.md): architecture, feasibility, YAML model reference, roadmap.
- [docs/ha-config.md](docs/ha-config.md): Home Assistant config generation.
- [docs/product-data.md](docs/product-data.md): vendor `.knxprod` files and generated models.

## Workspace layout

Crates in use: `bussard-model`, `bussard-project`, `bussard-transport`, `bussard-monitor`,
`bussard-mgmt`, `bussard-prod`, `bussard-ha`, `bussard-mcp`, `bussard-cli`. Reserved for
the downloader phase: `bussard-download`. See
[docs/DESIGN.md](docs/DESIGN.md) for what each crate does.

## Legal notes

- Never commit ETS project exports (`.knxproj`) or vendor product data (`.knxprod`) to a
  repository; the application XML is the manufacturer's copyrighted work. Users supply
  their own product files, obtainable free of charge from manufacturer service sites or
  the MyKNX catalogue. Details in [docs/product-data.md](docs/product-data.md).
- `bussard` is an independent project. It is not affiliated with, endorsed by, or
  certified by the KNX Association. KNX is a registered trademark of the KNX Association.

## License

[MIT](LICENSE)
