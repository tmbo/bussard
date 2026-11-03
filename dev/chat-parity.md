# Everything from chat: the workflows over MCP

Decision of 2026-11-03 by the owner: a user who drives bussard through an
assistant must be able to complete every workflow from chat. This supersedes
the line of 2026-09-30 that kept `flash` of a new application, `adopt`,
`replace` and `commission` on the command line.

The unit is the workflow, not the command. The CLI serves someone who wants
the exact command and its flags; chat serves someone who says what they want
done. So the MCP side does not mirror the command list one to one: where the
CLI has three commands for one task, chat gets one tool that runs the task,
asks the one question that matters and reports in sentences. Fewer tools
also means less text the assistant reads on every turn.

Two things stay out, unless the owner decides otherwise:

- A group address marked `protected = true` is still refused over MCP with
  no override. `bussard write --force` at the terminal stays the only way.
- The KNX Secure activation of a factory-fresh device (the FDSK step) stays
  with ETS. bussard does not implement it on either surface.

## The workflows, and where chat falls short today

The tasks are the ones the user docs list (`docs/how-to/index.md` and the
getting-started pages). 48 tools on main (`e39a2fc6`).

| Workflow | At the terminal | In chat today | Missing in chat |
|---|---|---|---|
| Set up the house | `init`, `import` | nothing: the server needs an existing model directory | `knx_setup`: start the server on an empty folder, discover the gateway, import the ETS export if there is one |
| Bring in files from ETS or a vendor | `import`, `import-product`, `keys import` | `.knxproj` only, at the terminal | one `knx_import_file` that takes a `.knxproj`, a `.bussard` bundle, a `.knxprod` or a `.knxkeys` and does what the file type needs |
| Hand over, export, document | `export`, `export-groups`, `keys export`, `doc` | `knx_export_bundle` | `knx_export` with `what: bundle, groups, keyring, doc` (the bundle form replaces `knx_export_bundle`) |
| Watch the bus | `monitor`, `capture`, `read`, `viz` | `knx_recent_telegrams`, `knx_wait_for_telegram`, `knx_read_group` | nothing; a recording to a file and the browser page are terminal things |
| Find what you have | `audit`, `scan`, `describe`, `status <ia>`, `reconstruct` | `knx_audit`, `knx_describe_device`, `knx_reconstruct_device` | `knx_find_devices` (the line scan, as a job); a `live` form of the device status (identity, IP settings, tunnel slots) on `knx_show_device` |
| Change what a button does, change a parameter | edit, `plan`, `apply`; `flash` when the application changes | the edit tools, `knx_plan_device`, `knx_apply_device`; the plan says "needs `bussard flash`" | `knx_apply_device` runs the flash itself when the plan needs one, under the same digest; a `line` argument on plan, apply and reconstruct |
| Add a device | `scan`, `adopt` (or `assign` + `import-product` + edits), `flash` | nothing | `knx_add_device`: one flow from "press the button" to the verified device, product data fetched with one consent |
| Back up and replace | `backup`, `restore`, `replace` | `knx_backup_device`, `knx_restore_tables`, `knx_restore_parameters` | `knx_replace_device`: backup, press the button, flash, apply, record, one `yes` |
| Commission a line | `groups reserve`, `commission`, `test`, `doc` | `knx_reserve_groups`, `knx_scaffold_groups`, `knx_run_tests` | `knx_commission_line`: per device, press the button, verify the order number, assign, label text |
| Exchange with ETS, work with an integrator | `export-groups`, `diff`, `export`, `import` | `knx_diff_project`, `knx_export_bundle` | covered by `knx_export` and `knx_import_file` above |
| Home Assistant | `ha-config` | the HA tier | nothing |
| KNX Secure | `keys`, `interface secure`, `secure diag` | `knx_interface_secure`, the Secure diagnostics | the keyring forms of `knx_import_file` and `knx_export` |

Not carried into chat on purpose: `assign` on its own (it is the first step of
adding a device, and `knx_add_device` runs it), `capture` to a file, `viz`
(a browser page; the assistant names the command), `learn` (the
`knx_infer_group` loop is the chat form).

Net new tools: `knx_setup`, `knx_import_file`, `knx_export` (absorbing
`knx_export_bundle`), `knx_find_devices`, `knx_add_device`,
`knx_replace_device`, `knx_commission_line`, `knx_job_status`. Eight, for
sixteen CLI commands.

## Why the gap exists

The lifecycle commands were written as terminal programs. Their logic lives in
`crates/bussard-cli` with the prompts inline: `assign_cmd.rs` 1211 lines,
`adopt_cmd.rs` 1594, `flash_cmd.rs` 2535, `commission_cmd.rs` 974,
`replace_cmd.rs` 751, `init_cmd.rs` 1305, `line_cmd.rs` 1296. The service
crate holds pieces (`bussard-service/src/adopt.rs`, `flash.rs`,
`identity.rs`) but not the sequences. A tool cannot call a function that asks
a question on stderr, so each flow moves down a layer first. That is the
design change; the tools on top are thin.

## Principles

1. **One flow, two front ends.** Each flow moves into `bussard-service` as a
   step machine with no I/O of its own. The CLI keeps the prompts and the
   printing; the tool keeps the questions and the JSON. The #314 rule (the
   CLI and the MCP server call the same function) then holds for every
   write.
2. **A physical step is a wait, not a prompt.** "Press the programming button
   on the new device" becomes a `question` in the tool result and a job that
   waits for the programming-mode broadcast as long as the CLI does
   (`PROGRAMMING_WAIT_TOTAL`, 30 s), then reports what answered. The
   assistant relays the question to the human and polls.
3. **Every long operation is a job.** `apply_jobs::ApplyJobs` becomes one job
   table for every tier, read by `knx_job_status`. `knx_apply_status` stays
   registered under its old name so existing clients keep working.
4. **Consent is the plan digest, as for `apply`.** A flow that writes a
   device returns the plan and a `plan_digest`; the write call presents that
   digest and `yes: true`. The digest binds the device, the application, the
   serial number where there is one and the model content, and is refused
   when a fresh read no longer produces it. Downloading vendor product data
   is a separate consent, `download: true`, exactly as `--download` at the
   CLI (`confirm.rs`, `DOWNLOAD_FLAG`): `yes` never answers it.
5. **No new tier.** `--allow-programming` is the owner's one switch for "the
   assistant may program devices"; it covers add, replace and commission and
   the flash inside apply, with the same loopback or `--allow-remote-gateway`
   rule. `knx_find_devices` and the live status only read and join the
   default tier. `knx_setup`, `knx_import_file` and `knx_export` join every
   tier; the two that write the model follow `--no-model-edits`.
6. **The server starts before the model exists.** `bussard mcp --dir <dir>`
   on a missing or empty directory starts in an onboarding state with
   `knx_setup` and `knx_bus_status` only. After `knx_setup` it registers the
   full set and sends `notifications/tools/list_changed`. The chat path is:
   install bussard, register the server on an empty folder, say "set up my
   house".
7. **Verification does not change.** Every write ends with the independent
   read-back the CLI does, the offline oracle row that covers the CLI command
   covers the tool (same function), and a silent success stays a P1.
8. **The guidance shrinks as the tools land.** `guidance.rs` names what still
   needs the CLI (`CLI_ONLY`) and ETS (`ETS_ONLY`) in the server
   instructions, pinned by a guard test (#272, #273). Each PR that closes a
   gap edits that string and that test. Results speak in the sentences of
   #306: names first, ids only where the next tool call needs them.

## The shape of a flow

`knx_add_device` as the example; `knx_replace_device` and
`knx_commission_line` use the same step and job shape.

```text
knx_add_device {address: "1.1.42", order_number: "2138.10 REG"}
  → {step: "press_button", job: "j7", question: "Press the programming
     button on the new device, then say done."}

knx_job_status {job: "j7"}
  → {step: "identified", serial: "...", mask: "07B0", order_number: "...",
     product_data: "would download 2138.10 REG from the vendor index (1.2 MB)",
     plan_digest: "sha256:...", sentences: [...],
     question: "Assign 1.1.42, fetch the product data and write the links
     above? Say yes."}

knx_add_device {job: "j7", plan_digest: "sha256:...", yes: true, download: true}
  → {step: "done", assigned: true, verified: true, summary: "...",
     next_step: "..."}
```

`knx_commission_line` repeats `press_button` → `identified` → `assigned` per
device of the line and returns the label text the CLI prints.
`knx_replace_device` runs backup, `press_button`, flash, apply and the lock
update as one job with one `yes`, as the CLI does. `knx_apply_device` with a
plan that needs the application loaded says so in the sentences, and the
`yes` covers the flash and the apply together.

A tool call may be cut by the client after 60 s, so no step blocks longer
than that: the wait for the button is a job, the flash is a job, the line
sweep is a job.

## Phases

Each phase is one or more PRs from worktrees off `main`, one implementation
agent per item (`dev/agent-brief.md`). An item that writes a device names its
oracle rows and ends with the read-back. Epic #755 links one issue per item.

1. **Files and setup, no refactor.** `knx_import_file` (#743), `knx_export`
   (#744), then `knx_setup` with the onboarding state (#745). These call `bussard-prod`,
   `bussard-project` and the key store as the CLI does.
2. **Jobs and reads.** One job table and `knx_job_status` (#746);
   `knx_find_devices` and the live status (#747); the `line` argument on
   plan, apply and reconstruct (#748).
3. **Flows.** Each first moved into `bussard-service` with the CLI rewired
   onto it, then exposed: the assign step and `knx_add_device` (#749), the
   flash inside `knx_apply_device` (#750), `knx_replace_device` (#751),
   `knx_commission_line` (#753).
4. **Docs and guidance.** The user docs get linked tabs, "In chat" and "At
   the terminal", on every task page; the getting-started pages offer both
   entry points; `docs/reference/mcp-tools.md` and the server instructions
   drop the CLI-only list (#754).

Done when the `CLI_ONLY` string in `guidance.rs` is empty and every task page
carries both tabs.
