# bussard

An open-source, cross-platform CLI for KNX. No GUI, ever.

`bussard` (German for buzzard — a bird that watches the field from above, and it contains
"bus") aims to replace ETS for day-to-day work on an existing KNX installation:

- **Configuration as code.** Group addresses, links, and device parameters live in YAML
  files in a git repo — so changes are reviewable diffs, and an LLM can propose them
  safely.
- **Terraform-shaped workflow.** `import → validate → plan → apply`: bootstrap the model
  from an existing ETS project, check it, preview the change, push it to the devices over
  the bus.
- **Bus observation.** Live monitor, telegram capture, and decoding against the same YAML
  model — plus an MCP server so LLMs can debug the installation.

**Status: early development.** Phase 0 (read-only: import, validate, monitor, capture,
MCP) works — see [docs/getting-started.md](docs/getting-started.md). Writes and the
device downloader come next; see the
[milestones](https://github.com/tmbo/bussard/milestones).

## Design goals

- Easy and quick to install: a single static binary (Homebrew / winget / Scoop /
  `curl | sh`), no runtime.
- Primary target: home owners and small installations.
- Speed everywhere — sub-second to first frame, pipelined multi-device operations,
  differential downloads.
- All configuration is file based.
- Fail fast and fail gracefully — never leave the KNX system in an inconsistent state.

Non-goals: replacing ETS for certification, planning, or documentation; supporting every
KNX device ever made; any graphical interface.

## Getting started

Build and install from this repo (prebuilt binaries are planned):

```
cargo install --path crates/bussard-cli
```

Two ways in. **Have an ETS project?** `bussard import project.knxproj` populates
the model, then `bussard validate` and `bussard monitor` give you a live,
decoded bus. **No ETS project?** `bussard init` discovers your gateway and writes
an empty model to watch with `bussard monitor`.

See [docs/getting-started.md](docs/getting-started.md) for the full walkthrough,
including the MCP setup for LLM-assisted debugging.

## CLI surface

Everything below works today except the commands marked *planned*, which land
in later phases.

```
bussard init                          # discover the gateway, write an empty model
bussard import project.knxproj        # bootstrap YAML from an existing ETS project
bussard validate [--format json]      # schema + semantic checks on the YAML
bussard monitor [--filter EXPR]       # live bus, decoded against the model
bussard capture --to bus.db           # persistent telegram store
bussard read 3/2/0                    # group value read
bussard write 3/0/4 down [--force]    # group value write
bussard ha-config [--out FILE]        # generate the Home Assistant KNX config
bussard mcp [--passive|--allow-writes]# serve MCP over stdio
bussard scan 1.1                      # find devices, report mask version   (planned)
bussard import-product dev.knxprod    # generate a device model from .knxprod (planned)
```

## Workspace layout

Phase 0 crates: `bussard-model`, `bussard-project`, `bussard-transport`,
`bussard-monitor`, `bussard-mcp`, `bussard-cli`. Reserved for later phases:
`bussard-mgmt`, `bussard-prod`, `bussard-download`.

See [docs/DESIGN.md](docs/DESIGN.md) for the architecture, the technical background on why
this is feasible, and the roadmap.

## Legal notes

- Never commit ETS project exports (`.knxproj`) or vendor product data (`.knxprod`) to a
  repository — the application XML is the manufacturer's copyrighted work. Users supply
  their own product files, obtainable free of charge from manufacturer service sites or
  the MyKNX catalogue.
- `bussard` is an independent project. It is not affiliated with, endorsed by, or
  certified by the KNX Association. KNX is a registered trademark of the KNX Association.

## License

[MIT](LICENSE)
