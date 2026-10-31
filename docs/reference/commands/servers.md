# Server and report commands

The long-running servers and the installation reports: `mcp` (the assistant's connection), `viz` (the web view), `ha-config` (Home Assistant YAML) and `audit`.

## `bussard mcp`

Run the MCP server over stdio, so an LLM assistant can read the model, watch the bus and, at higher tiers, write. An MCP client starts the server itself; nothing connects to it.

```console
$ bussard mcp --dir knx
```

Started from a terminal, the server prints how to register it once it is ready: the Claude Code command, `claude mcp add knx -- <binary> mcp --dir <model dir> <your flags>`, and the same server as a `mcpServers` JSON entry for Claude Desktop and other clients. Both use the absolute path of the running binary and the resolved model directory, so the registration does not depend on the client's working directory. Relative `--keyring` and `--capture-db` paths are made absolute.

| Flag | Default | Meaning |
|---|---|---|
| `--passive` | off | Never transmit on the bus; omits `knx_read_group`, `knx_describe_device` and `knx_bus_reconnect`. |
| `--allow-writes` | off | Register `knx_write_group` and `knx_run_tests`. Mutually exclusive with `--passive`. |
| `--allow-programming` | off | Register the programming tier: `knx_plan_device`, `knx_apply_device`, `knx_apply_status`, `knx_last_apply`, `knx_restore_parameters`, `knx_clear_security_log` and `knx_interface_secure`. Mutually exclusive with `--passive`. |
| `--plan-ttl-minutes <MINUTES>` | `10` | How long a `knx_plan_device` digest stays valid for `knx_apply_device`. Needs `--allow-programming`. |
| `--allow-remote-gateway` | off | Permit `--allow-writes` or `--allow-programming` against a non-loopback (real) gateway. Without it (or `BUSSARD_ALLOW_REAL_GATEWAY=1`) such a server refuses to start. |
| `--no-model-edits` | off | Withhold the model-edit tools (`knx_set_group`, `knx_remove_group`, `knx_add_link`, `knx_remove_link`, `knx_set_device`, `knx_set_parameter`, `knx_set_interface`, `knx_undo`, `knx_discard_edits`, `knx_scaffold_groups`, `knx_reserve_groups`). They write the model's TOML files behind a history snapshot and never touch the bus, so they are registered by default. |
| `--allow-home-assistant` | off | Register the Home Assistant tier (`knx_ha_status`, `knx_ha_plan`, `knx_ha_apply` and the three automation tools) when `bussard.toml` has a `[home_assistant]` table. Never touches the bus, so it combines with every tier, `--passive` included. Without the table the flag logs a warning and registers nothing. |
| `--capture-db <PATH>` | | A `bussard capture` database that extends `knx_recent_telegrams` history beyond the in-memory ring. |
| `--keyring <FILE>` | the key store | ETS keyring export (`.knxkeys`) for KNX Data Secure. Password from `BUSSARD_KEYRING_PASSWORD`. See below. |

What `--keyring` covers:

- `knx_describe_device` and `knx_plan_device` wrap their session with the target's tool key, as `bussard describe --keyring` and `bussard plan --keyring` do. A device the keyring does not list is read in the clear through the secure tunnel, unless the model marks it `security.activated`; then they refuse.
- `knx_apply_device` writes a device the keyring lists over KNX Data Secure and reprograms its security object, as `bussard apply --keyring` does.
- Its group keys secure `knx_read_group` and `knx_write_group` on a secured group address (the results carry `secured`). A secured group address without a key is refused.
- Secured telegrams on the live bus are decrypted (`knx_wait_for_telegram`, `knx_recent_telegrams`, `knx_infer_group`), and so are those re-decoded from `--capture-db`.
- `knx_validate` checks the keyring against the model.

Behaviour:

- The tiers, what each tool does and the gates in front of the programming and Home Assistant tiers are on [MCP tools](../mcp-tools.md).
- Every device or Home Assistant write over MCP needs a plan the human approved with an explicit yes in the conversation, checked by a single-use, time-limited plan digest.
- No password is printed. When `BUSSARD_KEYRING_PASSWORD` (or the `--secure-password-env` variable) is exported, a line says the client must provide it and the JSON carries a `<password>` placeholder. When it comes from the `.env` in or next to the model directory, a line says the server reads that file itself.
- A client that spawns the server with piped stderr gets none of the registration text, only the info-level log line `mcp: serving on stdio` (visible with `-v`).

**Claude Desktop.** Settings > Developer > Edit Config opens `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`). Paste the entry and restart Claude Desktop. The server shows under the tools icon in a chat, not in the connector list. The custom connector dialog takes only the HTTPS URL of a remote server, which would need an HTTP transport; bussard does not offer one.

## `bussard viz`

Serve the network-visualization website: an HTTP server that renders the model as a bus-spine diagram and streams live traffic.

```console
$ bussard viz
```

Open the listen address (`http://127.0.0.1:8080` by default) in a browser. The page is self-contained: no CDN, no build step, and it works offline.

| Flag | Default | Meaning |
|---|---|---|
| `--listen <ADDR>` | `127.0.0.1:8080` | The address to bind the HTTP server to. A non-loopback bind is allowed but warns: the port is unauthenticated. |
| `--gateway <HOST>` | | Gateway override. On connect failure the server degrades to model-only mode. |
| `--watch-prog` | off | Watch for devices in KNX programming mode and highlight them in the page. Active bus traffic: see below. |
| `--allow-writes` | off | Arm `POST /api/group-write`. Without it a bare `bussard viz` is a viewer, and the endpoint answers `403 writes_disabled`. |
| `--allow-remote-gateway` | off | Permit `--allow-writes` or `--watch-prog` against a non-loopback (real) gateway. Without it such a server refuses to start. |
| `--keyring <FILE>` | | Group keys (password in `BUSSARD_KEYRING_PASSWORD`). A write to a secured group address is sent as a secured group telegram (a secured address without a key answers `400`), and secured telegrams in the live traffic are decrypted. |
| `--allow-host <HOST>` | | Also answer requests whose `Host` header is this name (repeatable). Loopback names and bare IP literals are always accepted. |

The page shows the topology by floor and room, live traffic along the bus spine with a filterable log, the last value of each group address, a problems panel (com-objects without a link, group addresses without a sender or listener), per-DPT test-write widgets, an inspector with the selected device's com-objects and parameter values, and a `?` help panel.

Behaviour:

- Structure is read-only: devices, groups and links are edited in the model files. The reload button next to the bus status re-reads the model and `bussard.lock` without a restart and keeps the traffic view; use it after an `import` or `apply`.
- Writes are off by default. With `--allow-writes`, every send asks for a confirmation naming the group address and the resolved gateway, and a `protected` group address also needs the force checkbox.
- `--watch-prog` broadcasts `A_IndividualAddress_Read` every few seconds. It is off by default and takes effect only when a bus is connected. Never point it at a real installation unattended.
- The listen port is unauthenticated: anything that reaches it can read the whole model and, with `--allow-writes`, write to the bus. Keep the default loopback bind unless you have a reason not to.
- A request whose `Host` header is not a bare IP literal, `localhost` (or a `*.localhost` name) or an `--allow-host` name gets `403 forbidden`. This stops DNS rebinding.
- A `POST` whose `Origin` is not an allowed host gets `403 forbidden`. A request with no `Origin` (for example `curl`) is allowed.
- If the gateway cannot be reached at startup, the server runs in model-only mode: everything but live traffic works, and writes return `503`. If the gateway drops mid-session, the server reconnects in the background; writes return `503` until the tunnel recovers. No restart is needed.
- The server takes one tunnel for the whole session. Whether another tool (a `bussard write`, `flash` or `scan`) can share the gateway at the same time depends on the gateway. To drive test traffic the page always sees, use the page's own writes.
- The endpoints are on [the viz API](../viz-api.md).

## `bussard ha-config`

Generate the Home Assistant KNX integration YAML from the model.

```console
$ bussard ha-config --out knx.yaml
```

| Flag | Default | Meaning |
|---|---|---|
| `--out <FILE>` | stdout | Output file. |

Behaviour:

- Reads the model and `ha.toml` only; nothing reaches the bus or Home Assistant.
- The derivation rules and the `ha.toml` overrides are on [Home Assistant](../home-assistant.md).
- The MCP server's Home Assistant tier writes the same YAML to the file Home Assistant reads, after a plan the human approved (see [MCP tools](../mcp-tools.md)).

## `bussard audit`

Report what the installation holds and what bussard can do with it. The static part reads only the model; `--live` adds a read-only look at the gateway and the bus.

```console
$ bussard audit
$ bussard audit --live --window 60
```

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Emit one JSON object instead of the sectioned text report: the same object the `knx_audit` MCP tool returns. |
| `--live` | off | Add the live part: gateway description, traffic sample, scan of the modelled devices. |
| `--window <SECS>` | `30` | Traffic-sample window for `--live`. |
| `--keyring <FILE>` | the key store | An ETS `.knxkeys` keyring. Each Secure device is reported with or without a tool-key entry, and with `--live` probed over KNX Data Secure with its tool key. Password from `BUSSARD_KEYRING_PASSWORD`. No key material is printed. |
| `--skip-address-check` | off | With `--live`, skip the check that no bus device answers at bussard's own source address before the scan (see [Device support](../../explanation/device-support.md)). |

Static sections (JSON keys in brackets):

- **Model** (`model`): device count per line, devices without a name or a location, group addresses without a DPT or a name (including ones only device files link), links to com-objects the device file does not declare, links for addresses with no device file, protected group addresses, project name and import source.
- **Findings** (`model.findings`): one-sided links only, a group address with senders but no listener or listeners but no sender. Unlinked com-objects and unused group addresses are counted in `model.info` as neutral information. The viz problems panel shows the same analysis.
- **Devices per mask** (`masks`): devices grouped by the `product.mask` their file records, with what bussard can do (`plan_apply`, `flash`, `reconstruct`, `describe`). The column comes from the same table the `plan`, `apply`, `flash` and `reconstruct` refusals use.
- **KNX Secure** (`secure`): Secure-capable and activated devices, and with `--keyring` whether the keyring holds each one's tool key.

Live sections (`live`, with `--live`):

- **Gateway** (`live.gateway`): name, individual address and `N tunnels, M in use` from the interface's description.
- **Traffic sample** (`live.traffic`): group telegrams seen during `--window`, per group address with its repetition rate, group addresses sent on the bus that have no listener in the model, and source addresses the model does not know.
- **Scan delta** (`live.scan`): every modelled device probed, one at a time and at most one probe per 250 ms, per line: which answered (with a mask mismatch against the model flagged) and which did not. Only modelled addresses are probed; unexpected devices show up as unknown traffic sources, or run `bussard scan`. A Data Secure device's row carries `secure` and the real mask when the secured probe read it; a hidden `FFFF` mask is never flagged as a mismatch.
- **KNX Secure (live)** (`live.secure`): every Data Secure device (one that answers the plain probe with mask `FFFF`, has a `security:` block in the model, or is in the keyring) with `activated`, `reachable_secured` (`null` when no secured probe ran), `plain_reads_refused`, `in_keyring` (`null` without `--keyring`), the real `mask`, and one `status`: `reachable_secured`, `key_refused`, `not_in_keyring`, `plain_reads_refused` (no keyring given), `plain`, or `not_answering`.

Behaviour:

- Read-only. The live part sends only management reads (device descriptor, authorize, device-object properties) to individual addresses, and never a group telegram.
- Exits 0 on a completed audit. A full interface (no free tunnel) stops the audit with exit code `4`.
- Each scanned device carries its identity verdict against `bussard.lock` (see [`plan`](programming.md)).

??? note "Details"
    Repetition counts frames marked repeated in the cEMI control field, and identical telegrams from the same source within 500 ms. The secured probe runs like `describe --keyring`: `S-A_Sync`, then the descriptor and device-object property reads inside `A_SecureData`.

## Related

- [MCP tools](../mcp-tools.md): every tool, the tiers and the bus connection.
- [The viz API](../viz-api.md): the JSON and SSE endpoints behind the page.
- [Connect an assistant](../../getting-started/assistant.md): register `bussard mcp` and hold the first conversation.
- [Find what you have](../../how-to/find-what-you-have.md): `audit` in a task.
