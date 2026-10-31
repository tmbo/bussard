# Environment variables

The variables bussard reads, and the `.env` file that can supply them. For the integrator who scripts bussard and for the owner who keeps passwords out of shell history.

A flag beats its variable, the variable beats `bussard.toml`, and `bussard.toml` beats the built-in default. The flags themselves are on [Global options](global-options.md).

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `BUSSARD_PROJECT_PASSWORD` | | Password for a protected `.knxproj` when `--password` is not given. Keep it in an untracked `.env`, never in the repository. |
| `BUSSARD_DIR` | discovered | The model directory when `--dir` is not given; beats [discovery](model-directory.md#discovery). From a `.env`, only the working directory's file counts (see [Which file](#which-file)). |
| `BUSSARD_GATEWAY` | `connection.gateway` | The gateway `host[:port]` when `--gateway` is not given; beats `connection.gateway` in `bussard.toml`. It only selects a gateway: a non-loopback one still needs `--allow-remote-gateway` for a write. |
| `BUSSARD_KEYRING` | | An explicit `.knxkeys` keyring when `--keyring` is not given; beats the key store `bussard.keys` and `connection.keyring` in `bussard.toml`. The password still comes from `BUSSARD_KEYRING_PASSWORD`. |
| `BUSSARD_KEYRING_PASSWORD` | | Password for the key store `bussard.keys` and for every `.knxkeys` export: passed with `--keyring`, named by `BUSSARD_KEYRING` or `connection.keyring`, found next to the project by `import` or `init`, or read and written by `bussard keys`. There is no flag for it on purpose, so it never lands in shell history or a process listing. |
| *(the `--secure-password-env` variable)* | | The KNXnet/IP Secure tunnelling user's password for `--secure-user`. You choose the variable's name; bussard reads only that variable. |
| `BUSSARD_ALLOW_REAL_GATEWAY` | off | Set to `1` to permit a write command against a non-loopback (real) gateway, the same as `--allow-remote-gateway`. Loopback gateways never need it. Only an exported variable counts: a `.env` that sets it is ignored with a warning. |
| `BUSSARD_HA_TOKEN` | | The Home Assistant long-lived access token for the MCP server's Home Assistant tier. `home_assistant.token_env` in `bussard.toml` names another variable. Exported or from the `.env`; never printed. |
| `BUSSARD_NO_DOTENV` | off | Set to `1` (exported) to skip the `.env` file entirely, for hermetic scripts. The `knx-sim` example scripts set it. |
| `RUST_LOG` | | Log filter, for example `debug` or `bussard_transport=trace`. Overrides `-v`/`--verbose` when set. |
| `BUSSARD_PRODUCT_INDEX` | built in | Path to a pointer index (JSON of the shape of `data/product-index.json`) that replaces the built-in one: a private mirror, or a test with `file://` URLs. See [Product data](product-data.md). |
| `BUSSARD_PRODUCT_CACHE` | on | Set to `off` (or `0`, `false`) to bypass the parsed-product cache under `.bussard/products/`, so every command parses the product archive again. |
| `BUSSARD_WIRE_TRACE` | off | Set to `1` to log every cEMI frame as hex on stderr, one `[wire] <UTC time, ms> TX >>` or `RX <<` line each, so per-frame timing can be read off the log. The diagnostic of last resort when a gateway behaves unexpectedly; very noisy. |
| `BUSSARD_SECURE_KEEPALIVE_SECS` | `30` | The KNXnet/IP Secure session keepalive interval in seconds; `0` sends none. The default is half the 60 s session timeout of the KNX specification. `bussard test --secure-idle` measures another interface's timeout. A value of 60 or more prints a warning at connect. |
| `BUSSARD_TCP_READ_DEADLINE_MS` | `5000` | The read deadline of a KNXnet/IP Secure (TCP) tunnel in milliseconds; `0` turns it off. The plain UDP tunnel ignores it. |
| `BUSSARD_TUNNEL_RECONNECT_SECS` | `60` | How long, in seconds, bussard tries to re-establish a lost gateway tunnel before the pending bus operation fails; `0` turns it off. While it runs, the log says `gateway connection lost` and later `gateway connection re-established`, and the progress display shows it as the last event. See [Safety](../explanation/safety.md). |
| `BUSSARD_FLASH_L4_TIMEOUT_MS` | | Flash knob: the per-exchange Layer 4 timeout. Raise it for a slow device or a lossy link. |
| `BUSSARD_FLASH_REBOOT_WAIT_MS` | 10 s, 30 s for Data Secure | Flash knob: the upper bound on the readiness poll after a restart. |
| `BUSSARD_SPARSE_MERGE_GAP` | `100` | Flash knob: the largest gap, in octets, the sparse writer writes through to join two runs of a System B image; `0` joins nothing. The device image is the same either way. System 7 parameter downloads keep a 4-octet gap. |
| `BUSSARD_FLASH_RECONNECT_EXCHANGES` | 10 for KNX Virtual, else off | Flash knob: cycle the L4 connection (disconnect, reconnect, re-authorize) once this many numbered exchanges have run on it, checked between steps. Unset, it is 10 for a KNX Virtual device (manufacturer `0x00FA`) and off for every other device, which keeps one connection like ETS. `0` turns cycling off everywhere. |
| `BUSSARD_FLASH_NO_HANDOVER` | off | Flash knob: set to `1` and `flash --yes` disconnects after the pre-flight and opens a fresh connection for the write phase, as it does without `--yes`, instead of taking over the pre-flight's connection. |

??? note "Details"
    - `BUSSARD_SECURE_KEEPALIVE_SECS`: a wrapped SESSION_STATUS `STATUS_KEEPALIVE` goes out at this interval.
    - `BUSSARD_TCP_READ_DEADLINE_MS`: after this long without any frame from the interface, the tunnel sends a CONNECTIONSTATE_REQUEST. No answer within the shorter of the deadline and 2 s counts as a lost link and starts the re-establish. The plain UDP tunnel detects a loss through its ACK timeout, within about 2 s.
    - `BUSSARD_FLASH_REBOOT_WAIT_MS`: the poll probes every 500 ms, from 0.5 s after the process time of a restart the device confirmed, or from 1.5 s after a bare `A_Restart`.
    - `BUSSARD_SPARSE_MERGE_GAP`: a gap is joined only when the joined run needs fewer memory-write requests than the two runs apart. The octets written into the gap are the ones the device already holds: the segment's fill, or the read-back memory on a parameters-only download. The default sits under the break-even of about 115 octets for a 200 ms request at 1.7 ms per octet.

Test-harness variables gate or shorten bussard's own test suites and are not meant for normal use: `BUSSARD_VIRTUAL_DEVICE*`, `BUSSARD_TEST_MULTICAST` and `BUSSARD_PRODUCT_CORPUS` select test inputs; `BUSSARD_ADDRESS_PROBE_MS`, `BUSSARD_ASSIGN_WAIT_MS`, `BUSSARD_BUS_BACKOFF_MS`, `BUSSARD_CONNECT_WAIT_MS`, `BUSSARD_MGMT_TIMEOUT_MS`, `BUSSARD_READ_TIMEOUT_MS` and `BUSSARD_SCAN_DISCOVERY_MS` shorten waits against a mock; `BUSSARD_FLASH_SYS7_LSM`, `BUSSARD_SECURE_ALGORITHM` and `BUSSARD_ORACLE_SALT` serve the simulator and offline comparisons.

## The `.env` file

bussard reads the `BUSSARD_*` variables from a `.env` file too, so you do not have to export the passwords and the gateway before every command. This applies to every command, `bussard mcp` included.

```
# knx/.env, never committed
BUSSARD_KEYRING_PASSWORD='s3cret # with a hash'
BUSSARD_GATEWAY=192.0.2.10
export BUSSARD_PROJECT_PASSWORD="project pw"
```

### Which file

bussard reads the first of these that exists, and only that one; files are never merged:

1. `<model dir>/.env`;
2. the `.env` in the directory that holds the model directory (the repository root for `knx/`);
3. `./.env` in the working directory.

The model directory decides the lookup, and `BUSSARD_DIR` can decide the model directory, so bussard resolves it in two steps. First the model directory: `--dir`, else an exported `BUSSARD_DIR`, else `BUSSARD_DIR` from `./.env`, else [discovery](model-directory.md#discovery). Then the lookup above runs from that model directory, and the file it picks supplies every other variable. When that is a different file, the working directory's `.env` contributed `BUSSARD_DIR` and nothing else.

### Precedence

- A flag beats everything.
- An exported variable beats the file, even when it is exported empty: `BUSSARD_KEYRING_PASSWORD= bussard validate` runs without a password whatever the file says.
- The file beats `bussard.toml` and the defaults.

### Keys

Only `BUSSARD_*` keys are read. Anything else in a shared `.env`, a Home Assistant token for example, is ignored and never enters bussard. `BUSSARD_ALLOW_REAL_GATEWAY` is never taken from the file: opening the write gate stays the flag or an explicit export (see [Safety](../explanation/safety.md)).

### Syntax

- One `KEY=value` per line, with an optional `export ` prefix.
- `#` comment lines and blank lines are allowed.
- A value may be wrapped in single or double quotes, which keep everything inside (`#`, spaces, `=`) verbatim.
- An unquoted value ends at a ` #` trailing comment.
- No `$VAR` interpolation, no escapes. CRLF line ends are fine.

### Output

No value is ever printed. `bussard -vv` logs which file was read and which keys it applied, and `--timing` names the file on its `dotenv` line. A `BUSSARD_ALLOW_REAL_GATEWAY` in the file gets a warning naming the key.

`BUSSARD_NO_DOTENV=1`, exported, skips the file.

## Related

- [Global options](global-options.md): the flags these variables stand in for, and their precedence.
- [Model directory](model-directory.md): how bussard finds the model directory the `.env` lookup starts from.
- [Safety](../explanation/safety.md): why the write gate never comes from a file.
