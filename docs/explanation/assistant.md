# The assistant over MCP

An LLM assistant can read your installation and edit the model freely, but
it reaches the bus only through tiers you switch on, and each physical step
waits for your explicit yes. This page explains the tiers and the rails on
each.

## Each tier adds to the one before

`bussard mcp` runs at one of four bus tiers, plus an optional Home Assistant
tier:

| Tier | Flag | What the assistant can do |
|---|---|---|
| Passive | `--passive` | Read and edit the model files, watch the bus. Nothing is transmitted. |
| Read | none | Also read group values and introspect devices, rate-limited. |
| Write | `--allow-writes` | Also send group values (`knx_write_group`, `knx_run_tests`). Protected addresses are refused. |
| Programming | `--allow-programming` | Also write one device's link tables and parameters after you approve the plan, replay a parameter backup (`knx_restore_parameters`), clear a Secure device's security failures log (`knx_clear_security_log`) and switch KNXnet/IP Secure of an IP interface (`knx_interface_secure`), each after your yes. Not with `--passive`. |
| Home Assistant | `--allow-home-assistant` | Read Home Assistant and rewrite its KNX configuration, each change after your yes. Never touches the bus. |

Model edits touch files only, at every tier; `--no-model-edits` withholds
them. A parameter value set with `knx_set_parameter` reaches a device through
the same plan and apply as a link. The server's instructions, each edit's
`next_step` and `knx_project_summary` state the active tier, so the assistant
tells you which push actually applies.

A write-enabled server pointed at a real gateway refuses to start without
`--allow-remote-gateway` or an exported `BUSSARD_ALLOW_REAL_GATEWAY=1`, as on
[Safety](safety.md). `knx_bus_reconnect` at the read tier only reopens the
connection to the interface and sends nothing onto the bus.

## Protected addresses have no override over MCP

At the CLI you can force a write to a `protected = true` group address with
`--force`. Over MCP no override exists, at any tier: the assistant cannot
write a protected address, rename or retype it, add or remove a link to it,
or set or clear the flag. `knx_run_tests` refuses a protected test whatever
`tests.toml` says, and a plan whose changes touch a protected address is
refused.

The asymmetry is deliberate. A human who types `--force` means to. An
assistant never gets that choice, so keep every dangerous address marked
`protected = true` and the MCP path can never touch it.
Any change near one is rendered with "This group address is protected." and
sorted to the top of `bussard status`.

## The programming tier writes one approved plan

`bussard mcp --allow-programming` gives the assistant the single-device
write of `bussard apply`: the link tables and the parameter octets that
differ, written by the same code the CLI runs. Every CLI gate applies, plus a
plan digest:

1. **Write gate.** Checked at startup and again on every call.
2. **Source-address check.** Both tools probe before they connect, as
   [Device support](device-support.md) describes.
3. **Plan digest.** `knx_plan_device` reads the device and returns the plan
   plus a `plan_digest`. `knx_apply_device` writes only when the digest came
   from the same session within `--plan-ttl-minutes` (default 10) and a fresh
   read reproduces it. A digest is single use.
4. **Your approval.** The assistant shows you the plan and calls
   `knx_apply_device` only after an explicit yes. The digest makes this
   checkable: an apply can only write what a plan showed.
5. **Protected addresses** in the plan refuse it.
6. **Identity.** A device whose application or mask differs from the lock is
   refused with the `bussard flash` it needs.

If ETS or another tool changed the device, or the model was edited, the
apply is refused and the digest retired. With `plan_hash`, the apply also
refuses when the device no longer produces the plan's `state_hash`, the
fingerprint `bussard plan --json` prints.

An apply then runs the CLI rails: the backups to `captures/backups/` (no
backup, no write), a history snapshot naming the gateway, the table write,
the parameter download, and a read-back of each. The result carries the
verify outcome, what was written and the backup paths. `apply --line` stays
CLI-only.

??? note "Details"
    The digest is a SHA-256 over the device address, the model's links and
    parameter values for it, the desired tables, the parameter image the
    write would stream, and the live tables and parameter memory it read.
    The history snapshot is named `mcp knx_apply_device <address> <digest>`.

## A com-object change becomes a flash

A parameter that shows or hides a com-object changes the group-object table,
which a parameter download does not rewrite. The same plan and apply pair
then flashes the device: the plan says `method: flash`, lists the
com-objects that appear or disappear, the table sizes, the parameter backup
and the pinned archive, and asks to flash. The device restarts and is offline
for the stated time, 30 to 50 seconds. It is the flash `bussard flash <ia>
--yes` writes, refused without an archive pinned in the lock, for a device
carrying another application, or whose load state cannot be read. A `flash`
that loads a new application stays CLI-only.

## Parameters are approved by name

The plan lists every parameter that differs by key, vendor text, device value
and model value, one sentence each. The write streams only the differing
octets, after the tables, and reads them back. Device-managed parameters
(values the application owns at runtime) never make a plan non-empty on
their own; the plan lists them with the role `device_managed`.

When the pinned product data is missing or changed, the plan leaves the
parameters out with the recovery line (`bussard import-product ...`) and says
it writes the links only. Once the archive is back, a new plan covers them.

## Secured devices follow the CLI

A device the server's keyring lists is planned and written over Data Secure,
as `bussard apply --keyring` does. The plan shows what the security object
receives (senders, keyed addresses, secured objects, never a key). A
`secure = true` address without a key refuses the plan, and a keyring or flag
change between plan and apply retires it. A device the model marks activated
but the keyring does not list is refused.

## The apply runs as a job

A client may cut a tool call at 60 seconds, which a secured apply with a
restart exceeds. `knx_apply_device` runs every gate, the snapshot and the
backups inside the call, and the write as a job in the server:

- A refusal in the pre-flight is the reply; nothing was written.
- The call waits up to 20 seconds. If the write ends, the reply is the full
  result; if not, it is `started: true` with a job id, and
  `knx_apply_status {job}` reports the step, the progress and the result.
- One apply per server at a time. Another apply or plan while a job runs is
  refused with the job's id.
- The job record is written to `apply-result.json` in its history snapshot.
  `knx_last_apply {address}` returns the latest job for a device, even after a
  server restart. A record a stopped server left running reads as
  `interrupted`: plan again before trusting the device.
- The status tools never touch the bus.

## The Home Assistant tier changes one file

`--allow-home-assistant` needs the `[home_assistant]` table in
`bussard.toml` as well; with only one of the two, the tools are not
registered.

- **Every change needs your explicit yes.** Reads are free (`knx_ha_status`,
  `knx_ha_plan`). A write goes through a plan, its sentences, your yes, and
  the same single-use, time-limited digest as device programming.
- **The token** comes only from the variable `home_assistant.token_env` names
  (default `BUSSARD_HA_TOKEN`) and appears in no result, error or log. Keep it
  in an untracked `.env`, and revoke it on your Home Assistant profile page
  when the laptop leaves.
- **One file.** Only `config_path` is written, and only when it is
  YAML-managed (a `knx:` package file, or the inside of a `knx: !include`).
  The old bytes go to `captures/backups/ha/` first and the replacement is
  atomic. Entities created in Home Assistant's UI are never touched.
- **Reload after success only.** The apply checks the token first, calls
  `knx.reload` only after the write, and reads the status again. A failed
  reload is reported with the backup path; restore by copying it back.
- **Automations.** bussard writes only ids starting with `bussard_` whose
  description carries `managed by bussard (model <dir>)`, and refuses a
  hand-made one. The previous JSON is kept under `captures/backups/ha/`
  before an update or removal. Every address must be in `groups.toml` with a
  matching DPT (data type), and none may be `protected`.
- **No other change.** The tier calls `knx.reload` and `automation.reload`
  and no other service.

## Undo takes back files, never the bus

bussard copies the model files to `<dir>/.bussard/history` before every
command that writes the model or the bus, and before every model edit over
MCP. `bussard status` says what changed since the last snapshot, `bussard
history` lists them, and `bussard undo` puts the files back.

`undo` sends nothing on the bus: after it, the installation behaves exactly
as before. The restored model reaches a device only when a human runs
`bussard plan <ia>` and `bussard apply <ia>`. An undo is snapshotted first, so
it can be undone.

Snapshots carry the model files (`bussard.toml`, `groups.toml`,
`bussard.lock`, `devices/*.toml`, and `tests.toml` and `ha.toml` when
present). A Data Secure switch of a group address also keeps a copy of the
encrypted key store, so `undo` restores the key. A snapshot never holds a
password, a plain key or vendor data. A bundle from `bussard export` holds the same files, the
snapshots and a manifest, copied from an allow-list: never `products/`,
captures, keyrings, `.knxproj` or `.knxprod` files, or `.env`. It carries your gateway address
in `bussard.toml`, and an import into an existing model keeps the
recipient's own. Importing a bundle writes files only.

## Next steps

- [Connect an assistant](../getting-started/assistant.md): set up the server and have a first conversation.
- [MCP tools](../reference/mcp-tools.md): every tool, its tier and its arguments.
- [History commands](../reference/commands/history.md): `history`, `show` and `undo`.
- [Home Assistant](../how-to/home-assistant.md): generate and tune the configuration.
