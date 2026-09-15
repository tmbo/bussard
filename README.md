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

**Status: early development.** Nothing is usable yet. Phase 0 (read-only: import, validate,
monitor, capture, MCP) is being built first — see the
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

## Planned CLI surface

```
bussard scan                          # find devices, report mask version, order number
bussard info 1.1.4                    # device descriptor, properties, load state
bussard monitor [--filter] [--decode] # live bus, decoded against the model
bussard capture --to bus.db           # persistent telegram store
bussard read 2/1/5                    # group value read
bussard write 2/1/5 --dpt 1.001 on    # group value write
bussard import project.knxproj        # bootstrap YAML from an existing ETS project
bussard validate                      # schema + semantic checks on the YAML
bussard plan                          # diff YAML vs. device state
bussard apply [--device 1.1.4]        # execute the download
bussard mcp                           # serve MCP over stdio
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
