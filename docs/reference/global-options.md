# Global options

The conventions, options, consent flags and exit codes that every `bussard` command shares. `bussard <command> --help` is authoritative for the build you run.

## Conventions

| Item | Form | Example |
|---|---|---|
| Group address (GA), the shared address a button and an actuator talk on | three levels | `3/2/0` |
| Individual address (IA), the address of one device | `area.line.device` | `1.1.4` |
| DPT, the datapoint type that says how a value is encoded | quoted string | `"1.001"` |
| Filter (`monitor --filter`, `capture --filter`) | comma-separated GAs, GA prefixes or IAs | `3/2/0,3/,1.1.30` |

**Confirmation.** A command that writes to a device or the bus asks `y/N` on a terminal and names the resolved gateway (`host:port`). Without a terminal it refuses unless you pass `--yes`. See [confirmation, download consent and JSON](#confirmation-download-consent-and-json).

**The real-gateway gate.** A write command whose resolved gateway is not loopback (`127.0.0.0/8` or `::1`) refuses to run unless you pass `--allow-remote-gateway` or set `BUSSARD_ALLOW_REAL_GATEWAY=1`.

- Loopback gateways, such as the local simulator, are always allowed.
- Reads (`monitor`, `read`, `scan`, `plan`, `reconstruct`) are never gated.
- The two servers pass the gate once, at startup, when a flag lets them transmit: `mcp --allow-writes`, `mcp --allow-programming`, `viz --allow-writes` and `viz --watch-prog`. The MCP programming tools check it again on every call.
- Without those flags neither server can write, so neither is gated.

Read [Safety](../explanation/safety.md) before your first write.

## Options

One option group serves every subcommand. Each option prints under "Global options" in every `--help` and goes before or after the subcommand: `bussard --dir site/knx status` and `bussard status --dir site/knx` are the same.

A command with no use for an option accepts and ignores it. The exception is `--json`, which a command without machine output refuses.

Precedence, for an option with more than one source: the flag, then the environment variable (exported, else from the `.env` file, see [Environment](environment.md)), then `bussard.toml`, then discovery or the built-in default.

| Option | Environment | `bussard.toml` | Default | Meaning |
|---|---|---|---|---|
| `--dir <DIR>` | `BUSSARD_DIR` | | discovered, see [model directory discovery](#model-directory-discovery) | The model directory. |
| `--gateway <HOST[:PORT]>` | `BUSSARD_GATEWAY` | `connection.gateway` | none: a tunnel without a gateway is an error | The KNXnet/IP gateway; the port defaults to 3671. Implies tunnelling. For `init`: use this gateway instead of discovering one (flag or environment only). |
| `--routing` | | `connection.transport = "routing"` | tunnelling | Use KNXnet/IP routing (multicast). No environment variable selects it, so a scripted multicast write shows on the command line. For `init`: configure routing. |
| `--keyring <FILE>` | `BUSSARD_KEYRING` | `connection.keyring` (deprecated) | the key store `bussard.keys` | The KNX Secure keys a bus command uses. See [keys](#keys). |
| `--json` | | | text | Machine-readable output: one JSON document with a top-level `"schema"`, or JSON Lines for `monitor`. Refused by a command without JSON output. `apply --json` needs `--line`. |
| `--allow-remote-gateway` | `BUSSARD_ALLOW_REAL_GATEWAY=1` (exactly `1`) | deliberately none | off | Permit a transmitting command (a write, programming, an armed `viz` or `mcp`) against a non-loopback gateway. Read-only commands ignore it. No other variable can enable a transmit. |
| `--skip-address-check` | | | off | Skip the pre-flight probe that no bus device answers at bussard's own source individual address, on the commands that open a device connection. See [Device support](../explanation/device-support.md). |
| `--refresh-facts` | | | off | Ignore the stored device facts and read them from the device again. Every management command that reads the facts honours it. |
| `-v`, `--verbose` | `RUST_LOG` overrides | | `warn` | Raise log verbosity; repeatable. `-v` is `info`, `-vv` `debug`, `-vvv` `trace`. An explicit `RUST_LOG` replaces this entirely, so `RUST_LOG=bussard_transport=trace` still works. `-v` also logs the model directory it chose. |
| `--timing` | | | off | Print the wall-clock time to stderr on exit (`took 1.23s`), preceded by the start-up phases that ran and how often the model was parsed and a keyring decrypted. |
| `--no-progress` | | | off | Never draw the live [progress display](#progress-display); print the plain progress lines, as a piped run does. |
| `--secure-user <ID>` | | | | Open a [KNXnet/IP Secure](#knxnetip-secure-tunnelling) tunnel as tunnelling user `ID`. Needs `--secure-password-env`. |
| `--secure-password-env <VAR>` | | | | The environment variable that holds the tunnelling user's password. Never on the command line. Needs `--secure-user`. |
| `--secure-transport auto\|tcp` | | | `auto` | How a refused TCP connect of the KNXnet/IP Secure session is reported. Both open TCP; `auto` names the likely causes. Needs tunnelling credentials. |

`--yes`, `--yes-download`, `--force`, `--dry-run` and `--plan` are not global. They stay on the command whose action they consent to, and never come from the environment or `bussard.toml`.

??? note "Details: the `--timing` phases"
    The phases are `tunnel creds` (the secure tunnel credentials), `model load`, `product parse` (programs parsed and whether the parsed-product cache was on), `tool keys`, `keyring` (the PBKDF2 keyring decrypt, part of the phase that needed it), `to tunnel open` (start to the tunnel request) and `tunnel`.

### Keys

`--keyring` names the keys three jobs use: the tunnelling users open the KNXnet/IP Secure tunnel, the device entries carry the KNX Data Secure tool keys for management, and the group keys secure and decrypt group telegrams.

1. An explicit `.knxkeys` file from `--keyring`, then `BUSSARD_KEYRING`.
2. Else the key store `bussard.keys` in the model directory (see [`bussard.keys`](files/bussard-keys.md)).
3. Else `connection.keyring` in `bussard.toml`. It is deprecated, kept for models without a store, and ignored with a warning when a store exists.

A relative `connection.keyring` is relative to the model directory; a relative flag or variable is relative to the working directory. The password comes from `BUSSARD_KEYRING_PASSWORD`, never a flag.

- Only commands that talk to the bus read the keys. `adopt` and `test` use them for the tunnel only.
- A key source other than `--keyring` serves the tunnel only when `--tool-key` is given.
- `--keyring` conflicts with `--tool-key`.

### Model directory discovery

Without `--dir` and `BUSSARD_DIR`, a command that reads an existing model looks for it the way `git` finds its root. It works from the repository root, from inside the model and from any subdirectory:

1. the working directory, when it holds `bussard.toml`;
2. `./knx`, when it exists;
3. each parent directory, nearest first: the parent when it holds `bussard.toml`, else its `knx/` when that holds `bussard.toml`;
4. otherwise the current directory.

A directory without a model file (`bussard.toml`, `groups.toml`, `bussard.lock` or `devices/`) is no model. A command that needs one says `no model in the current directory <path>: ...; run `bussard init` or `bussard import <export>` there, or pass --dir <model directory>`.

`init` and `import` create or update the model in `--dir`, `BUSSARD_DIR` or the current directory, and never search upward.

## Confirmation, download consent and JSON

### `--yes`

`--yes` means one thing on every command: skip the confirmation prompt.

- `assign`, `adopt`, `flash`, `apply`, `commission`, `restore`, `replace`, `restart`, `write`, `test` and `learn` ask on a terminal.
- Without a terminal and without `--yes` they refuse with `refusing to <action> without a terminal to confirm on; pass --yes to confirm non-interactively`.
- `assign`, `adopt`, `replace`, `commission` and `learn` refuse before they load the model.
- `flash`, `apply`, `restore`, `write` and `test` first read and show what they would change, then refuse at the prompt. `restart` refuses at its prompt, before it sends anything.
- An explicit address or value is never consent on its own.
- `--yes` never lifts the real-gateway gate, which is checked before the prompt.

### `--yes-download`

Downloading vendor product data is a separate question with its own flag, `--yes-download`, on `init`, `import`, `import-product` and `adopt`. `--yes` never answers it.

Without a terminal and without `--yes-download`, `init`, `import` and `adopt` download nothing and list the missing order numbers; `import-product --order-number` refuses. `--no-download` skips the question.

### `--force` and `--full`

These keep a per-command meaning.

- `--force` overrides one named refusal: the not-factory-fresh refusal (`flash`), the replacement-identity refusals (`replace`), or the protected-group-address refusal (`write`, `test`). `test` also needs `allow_protected = true` in the test file.
- `--full` means "skip nothing": `flash` re-streams every object, `describe` walks every property description again.

### JSON documents

Every `--json` document is one object whose first field is `"schema": <n>`, the version of that command's shape. Each `monitor --json` line carries it too. A list is wrapped under a key: `validate --json` prints `{"schema", "diagnostics": [...]}`.

The number goes up when a field is removed or renamed, or changes its type or meaning. Adding a field does not bump it, so ignore fields you do not know. Every shape starts at 1. The shapes are in [JSON output](json-output.md).

## KNXnet/IP Secure tunnelling

An interface with KNXnet/IP Secure on and no plain tunnel refuses an ordinary connection. bussard then needs a tunnelling user's credentials and opens an authenticated, encrypted session.

| Source | What happens |
|---|---|
| A keyring (automatic) | A command with a keyring (`--keyring` or the key store) uses its tunnelling users. When a keyring interface names the gateway's individual address and the gateway advertises KNXnet/IP Secure, the tunnel goes secure as the user whose tunnel address is free. The keyring's device authentication code lets bussard check the interface's identity first. A plain gateway stays on the plain tunnel. |
| `--secure-user <ID> --secure-password-env <VAR>` | Always opens a secure session as that user. Without a keyring the interface's identity is not verified; a warning says so. |
| Neither | Against a secure-only interface the command fails at once, with no retries: `interface <gateway> requires KNXnet/IP Secure (secure tunnelling only) and no tunnelling credentials were given ...`. |

`bussard init --gateway <ip>` prints `KNXnet/IP Secure: tunnelling is secure-only` for such an interface.

**One keyring, two jobs.** The keyring opens the tunnel, and its device entries carry the tool keys.

- A device the keyring lists is managed over KNX Data Secure with its tool key.
- A device it does not list is managed in the clear through the secure tunnel, so plain devices behind a secure-only interface stay reachable.
- A device whose model file says `security.activated: true` but that the keyring does not list is refused with `the keyring ... has no tool key for <IA>`. This holds for `describe`, `reconstruct`, `plan`, `flash`, `apply`, `commission`, `replace`, `backup`, `restore`, the `--line` walks and the MCP device tools.
- `scan`, `assign` and `audit --live` never refuse. A Data Secure-activated device without a tool key is labelled "Data Secure activated (mask hidden), no tool key in the keyring".

**TCP only.** A KNXnet/IP Secure tunnelling session runs over TCP, as ETS uses it. The KNX standard allows no other carrier: a unicast secure session must use TCP, and an interface discards a session request that arrives over UDP (KNX IP Secure 3/8/9 §2.2.3.3, §2.2.3.6.4). When the TCP connect is refused by an interface that advertises KNXnet/IP Secure, bussard fails with a message that names the likely causes: secure tunnelling disabled or misconfigured, the interface's TCP connections all taken (often there is just one), or a different device at that address.

**Tunnel addresses and sessions.** The interface assigns each authenticated user its own tunnel address, and management traffic uses it as its source.

- Two bussard processes on one host take different users. A user the interface refuses hands over to the next one.
- A refused password (`refused tunnelling user N`) and an interface that fails its own authentication are fatal.
- A lost link re-establishes a new session within the `BUSSARD_TUNNEL_RECONNECT_SECS` budget; a pulled cable is noticed after about 7 s.
- The session sends a keepalive every 30 s (`BUSSARD_SECURE_KEEPALIVE_SECS`). A value of 60 s or more prints a warning at connect. `bussard test --secure-idle <SECS>` measures how long an interface keeps an idle session.
- Secure routing (multicast) is not implemented.

The variables are on [Environment](environment.md).

??? note "Details"
    The handshake is X25519 key agreement; the interface proves its device authentication code, bussard proves the user password, and every later frame travels in a SECURE_WRAPPER. bussard reads the gateway's extended description to match it with a keyring interface. The tunnel marks the user it holds under `<dir>/.bussard/tunnel-users/`. A re-established session first closes the stale one, so an interface that allows one session per user does not refuse the new one as a second login.

    TCP carries no ACK, so after 5 s without a frame the tunnel sends a CONNECTIONSTATE_REQUEST and treats 2 s of further silence as a lost link (`BUSSARD_TCP_READ_DEADLINE_MS`). A UDP session detects a loss through its ACK timeout. Over UDP one socket carries the session and the tunnel, TUNNELING_ACKs travel inside the wrappers, every HPAI carries the real local endpoint and every frame goes to the control endpoint. The 30 s keepalive default is half the 60 s session timeout of the KNX specification.

## Progress display

`flash` (including `--parameters-only`), `apply`, `reconstruct --line` and `scan` show a live progress view on stderr when stdout and stderr are both terminals. It shows the step `k/n` and its label, a byte bar for the segment being streamed, the elapsed time, an ETA and the last bus event (a reboot wait, a reconnect, a connect retry).

A successful run clears the view and ends with the usual final lines. A failed run leaves it on screen, so the step it stopped at stays visible.

The view is off, and the output is the plain line-oriented text, when any of these holds:

- stdout or stderr is not a terminal;
- `TERM=dumb`;
- `BUSSARD_WIRE_TRACE=1`;
- the command runs with `--json`;
- `--no-progress` is given.

Progress never goes to stdout. The plain lines contain no cursor-control codes beyond the `\r` of the byte and address counters.

??? note "Details"
    The flash ETA starts from the plan's TP1 frame estimate and switches to the measured rate once 5% of the bytes are written.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Any other error or refusal. A network timeout exits `1`. |
| `3` | `import` re-imported the project but left hand-authored conflicts un-applied. The files were written with your edits intact; reconcile the reported fields. |
| `4` | The gateway has no free tunnelling connection (`E_NO_MORE_CONNECTIONS`, status `0x24`). Every tunnel slot is taken, usually by Home Assistant, an open ETS project or another bussard process. See [Device support](../explanation/device-support.md) for the tunnel budget. |

Cases worth knowing:

- `validate` exits non-zero on errors; warnings and infos alone exit 0.
- `read` exits non-zero when no response arrives within the timeout, so a script can detect a dead group object.
- `plan` and `apply` exit 0 when there is nothing to do.
- `import` exits `3` when a re-import kept hand-edited values that differ from the incoming side and no `--mine`, `--theirs` or `--interactive` settled them. The write still happened.
- Refusals (a protected GA without `--force`, no terminal without `--yes`, an unsupported device mask, an unsupported load procedure) exit non-zero before anything is written.
- `audit` exits 0 on a completed audit, whatever it found.

## Related

- [Environment](environment.md): the variables and the `.env` file.
- [Safety](../explanation/safety.md): the rules to read before the first write.
- [Write commands](../explanation/write-commands.md): what each write command does and its rails.
- [Model directory](model-directory.md): what lives in the directory `--dir` names.
