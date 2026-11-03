# Everything from chat: MCP parity with the CLI

Decision of 2026-11-03 by the owner: a user who drives bussard through an
assistant must be able to do everything the CLI does, from chat. This
supersedes the line of 2026-09-30 that kept `flash` of a new application,
`adopt`, `replace` and `commission` on the command line. The two modes of
use, chat and terminal, are then two front ends to one set of flows, and the
user documentation can offer every task in both forms side by side.

Two things stay out, unless the owner decides otherwise:

- A group address marked `protected = true` is still refused over MCP with
  no override. `bussard write --force` at the terminal stays the only way.
- The KNX Secure activation of a factory-fresh device (the FDSK step) stays
  with ETS. bussard does not implement it on either surface.

## The gap on 2026-11-03

48 tools on main (`e39a2fc6`). The CLI commands with no tool, and what each
needs. "Flow" means a sequence with a physical step or a confirmation in the
middle; "job" means an operation that outlives one tool call.

| CLI command | Over MCP today | Needed |
|---|---|---|
| `init` | nothing; the server needs an existing model directory | `knx_init` and an onboarding state of the server (below) |
| `import` (`.knxproj`, `.bussard`, JSON) | nothing | `knx_import` with the same password handling and the same download consent |
| `import-product` | nothing | `knx_import_product` (file path, or order number to fetch) |
| `keys show`, `keys import`, `keys export` | nothing | `knx_keys`; key material never crosses the wire, as at the CLI |
| `export-groups` | nothing | `knx_export_groups` |
| `doc` | nothing | `knx_render_doc` |
| `status <ia>` (live identity, IP settings) | partly `knx_describe_device` | `knx_device_status` |
| `scan` | nothing | `knx_scan_line`, a job |
| `assign` | nothing | `knx_assign_address`, a flow with one physical step |
| `adopt` | nothing | `knx_adopt_device`, a flow |
| `flash` (fresh device or new application) | parameters only, inside the apply job | `knx_flash_device`, plan digest and a job |
| `replace` | nothing | `knx_replace_device`, a flow |
| `commission` | nothing | `knx_commission_line`, a flow repeated per device |
| `plan --line`, `apply --line` | one device per call | a `line` argument on `knx_plan_device` and `knx_apply_device` |
| `reconstruct --line` | one device per call | a `line` argument on `knx_reconstruct_device` |
| `capture` | `knx_recent_telegrams` holds a window in memory | `knx_capture` to record to a file for a duration, a job |

Already covered and staying as they are: `monitor` (`knx_recent_telegrams`,
`knx_wait_for_telegram`), `learn` (`knx_infer_group` and the edit tools),
`backup`, `restore`, `restart`, `reconstruct <ia>`, `plan`, `apply`,
`validate`, `history`, `undo`, `diff`, `export`, `audit`, `test`, `write`,
`read`, `groups reserve`, `interface secure`, `secure diag`, Home Assistant.
`viz` is a browser page, not a chat action; the assistant names the command.

## Why the gap exists

The lifecycle commands were written as terminal programs. Their logic lives in
`crates/bussard-cli` with the prompts inline: `assign_cmd.rs` 1211 lines,
`adopt_cmd.rs` 1594, `flash_cmd.rs` 2535, `commission_cmd.rs` 974,
`replace_cmd.rs` 751, `init_cmd.rs` 1305, `line_cmd.rs` 1296. The service
crate holds pieces of them (`bussard-service/src/adopt.rs`, `flash.rs`,
`identity.rs`) but not the flow. An MCP tool cannot call a function that asks
a question on stderr, so each flow has to move down a layer first. That is the
design change; the tools on top are small.

## Principles

1. **One flow, two front ends.** The flow of each command moves into
   `bussard-service` as a function or a step machine with no I/O of its own.
   The CLI keeps the prompts and the printing; the MCP tool keeps the
   questions and the JSON. The #314 rule (the CLI and the MCP server call the
   same function) then holds for every write, not only `apply`.
2. **A physical step is a wait, not a prompt.** "Press the programming button
   on the new device" becomes a `question` in the tool result and a job that
   waits for the programming-mode broadcast as long as the CLI does
   (`PROGRAMMING_WAIT_TOTAL`, 30 s), then reports what answered. The
   assistant relays the question to the human and polls.
3. **Every long operation is a job.** `apply_jobs::ApplyJobs` becomes one job
   table for every tier, read by `knx_job_status`. `knx_apply_status` stays
   registered as the same tool under its old name so existing clients keep
   working.
4. **Consent is the plan digest, as for `apply`.** A flow that writes to a
   device returns the plan and a `plan_digest`; the write call must present
   that digest and `yes: true`. The digest is bound to the device, the
   application, the serial number where there is one, and the model content,
   and it is refused when a fresh read no longer produces it. Downloading
   vendor product data is a separate consent, `download: true`, exactly as
   `--download` at the CLI (`confirm.rs`, `DOWNLOAD_FLAG`): `yes` never
   answers it.
5. **No new tier.** `--allow-programming` is the owner's one switch for
   "the assistant may program devices"; it covers flash, assign, adopt,
   replace and commission as it covers apply, with the same loopback or
   `--allow-remote-gateway` rule. `knx_scan_line` and `knx_device_status`
   only read and join the default tier. The model-only tools (`knx_init`,
   `knx_import`, `knx_import_product`, `knx_keys`, `knx_export_groups`,
   `knx_render_doc`) join every tier; the ones that write the model follow
   `--no-model-edits`.
6. **The server starts before the model exists.** `bussard mcp --dir <dir>`
   on a missing or empty directory starts in an onboarding state with
   `knx_init`, `knx_import` and `knx_bus_status` only. After `knx_init` or
   `knx_import` it registers the full set and sends
   `notifications/tools/list_changed`. The chat path is then: install
   bussard, register the server on an empty folder, say "set up my house".
7. **Verification does not change.** Every write ends with the independent
   read-back the CLI does, the offline oracle row that covers the CLI command
   covers the tool (same function), and a silent success stays a P1.
8. **The guidance shrinks as the tools land.** `guidance.rs` names the
   commands that still need the CLI (`CLI_ONLY`) and ETS (`ETS_ONLY`) in the
   server instructions, and a guard test pins the text (#272, #273). Each PR
   that closes a gap edits that string and that test.

## The shape of a flow

`adopt` as the example; `assign`, `replace` and `commission` use the same
step and job shape.

```text
knx_adopt_device {address: "1.1.42", order_number: "2138.10 REG"}
  → {step: "press_button", job: "j7", question: "Press the programming
     button on the new device, then say done."}

knx_job_status {job: "j7"}
  → {step: "identified", serial: "...", mask: "07B0", order_number: "...",
     product_data: "would download 2138.10 REG from the vendor index (1.2 MB)",
     plan_digest: "sha256:...", sentences: [...],
     question: "Assign 1.1.42, fetch the product data and write the links
     above? Say yes."}

knx_adopt_device {job: "j7", plan_digest: "sha256:...", yes: true, download: true}
  → {step: "done", assigned: true, verified: true, summary: "...",
     next_step: "..."}
```

`commission` repeats `press_button` → `identified` → `assigned` per device
of the line and returns the label text the CLI prints. `replace` runs
backup, `press_button`, `flash`, `apply` and the lock update as one job with
one `yes`, as the CLI does.

A tool call may be cut by the client after 60 s, so no step blocks longer
than that: the wait for the programming button is a job, the flash is a job,
the line sweep is a job.

## Phases

Each phase is one or more PRs from worktrees off `main`, one implementation
agent per item (`dev/agent-brief.md`). An item that writes to a device names
its oracle rows and ends with the read-back.

1. **Model-only tools, no refactor.** `knx_import_product`, `knx_keys`,
   `knx_export_groups`, `knx_render_doc`; then `knx_init` and `knx_import`
   with the onboarding state. These call `bussard-prod`, `bussard-project`
   and the key store directly, as the CLI does.
2. **Jobs and reads.** One job table and `knx_job_status`; `knx_scan_line`;
   `knx_device_status`; the `line` argument on plan, apply and reconstruct;
   `knx_capture`.
3. **Flows.** In this order, each one first moved into `bussard-service`
   with the CLI rewired onto it, then exposed: `assign`, `adopt`, `flash`,
   `replace`, `commission`.
4. **Docs and guidance.** The user docs get linked tabs, "In chat" and "At
   the terminal", on every task page; the getting-started pages offer both
   entry points; `docs/reference/mcp-tools.md` and the server instructions
   drop the CLI-only list.

Tracking: the epic issue links one issue per item and is closed when the
`CLI_ONLY` string in `guidance.rs` is empty and the docs carry both tabs on
every task page.
