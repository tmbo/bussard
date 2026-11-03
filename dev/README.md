# Maintainer documentation

The pages in this directory are for people working on bussard: design notes,
implementation specs, test runbooks and the brief for implementation agents.
User documentation lives in [`docs/`](../docs/index.md) and is published at
[bussard.tmbo.dev/docs](https://bussard.tmbo.dev/docs/); nothing in `dev/`
is rendered there.

| Page | What it is |
|---|---|
| [docs-guide.md](docs-guide.md) | How the user documentation is written: the reader, page anatomy, style rules, the page map. |
| [agent-brief.md](agent-brief.md) | Standing instructions for an implementation agent: worktree rules, commands, PR steps, report shape. |
| [DESIGN.md](DESIGN.md) | The living design document: goals, feasibility, architecture, roadmap. |
| [chat-parity.md](chat-parity.md) | Everything from chat: the gap between the CLI and the MCP tools, the flow and job shape that closes it, the phases. |
| [testing.md](testing.md) | How ETS, bussard and knx-sim check each other, how to run the test suites, the gated corpus tests, the simulator loop and the test knobs. |
| [testing-campaign.md](testing-campaign.md) | Runbook for the physical-device campaign and the offline oracle. |
| [flash-op-coverage.md](flash-op-coverage.md) | Which LoadProcedure ops the corpus uses, which `flash` executes, and the clause of the standard behind each (System B). |
| [system7-spec.md](system7-spec.md) | Implementation spec for the System 7 download path (masks 0705 and 0701). |
| [knx-secure-spec.md](knx-secure-spec.md) | Implementation spec for KNX Data Secure and KNXnet/IP Secure. |
| [product-model-format.md](product-model-format.md) | Field-by-field description of the generated product model files. |
| [personas/](personas/README.md) | The owner and integrator personas, their journeys and the issue drafts derived from them. |
| `knx-standard-3.0.0/` | The KNX Standard 3.0.0 text (`_txt/`, pdftotext of every volume), licensed and read-only: cite document, section and page in notes and issues, never paste paragraphs or tables; it is not committed. The 3.0.0 review of the System 7 and System 2 clauses is folded into [system7-spec.md](system7-spec.md). |

## Claude Desktop and a dev build (macOS)

macOS grants Local Network access per code identity. A `cargo build` binary
is ad-hoc signed, so every build has a new identity: when Claude Desktop
starts the rebuilt `target/debug/bussard`, the grant moves to it and an
older `bussard mcp` still running loses network access at once (its error is
`LocalNetworkDenied`). To keep a dev session's server stable, point
`claude_desktop_config.json` at a copy that `cargo build` does not overwrite
(`cp target/debug/bussard ~/.local/bin/bussard-mcp`, refreshed when you want
the new build and followed by a Desktop restart), or sign the dev binary
with a stable identity (`codesign -s "<your Apple Development identity>" -f
target/debug/bussard`).

## Private data

The repository must never describe a real installation. Raw installation data
(`knx/`, `*.knxproj`, `*.knxkeys`, captures, `shared-with-windows/`, the
product corpus cache) is gitignored. Fixtures, examples and tests use invented
names and TEST-NET addresses; review a diff for room names, device names and
LAN addresses before you commit it. If you flash your own house, keep your
`knx/` out of any fork you publish.
