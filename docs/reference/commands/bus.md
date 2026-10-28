# Bus commands

The commands that listen to group telegrams, read and write group values, name addresses from live traffic and run acceptance tests: `monitor`, `capture`, `read`, `write`, `learn` and `test`. Global options and exit codes are on [Global options](../global-options.md).

## `bussard monitor`

Live-monitor the bus and decode each telegram against the model. Reads only; never transmits.

```console
$ bussard monitor [--filter <EXPR>] [--keyring <FILE>] [--json]
```

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Emit JSON Lines (see [JSON output](../json-output.md)) instead of the text format. |
| `--filter <EXPR>` | all | Only show matching telegrams: a comma-separated list of GAs, GA prefixes (`3/`, `3/2/`) or IAs. |
| `--keyring <FILE>` | the key store | Keys to verify and decrypt KNX Data Secure group telegrams. The password comes from `BUSSARD_KEYRING_PASSWORD`. |

Behaviour:

- A group address (GA) or DPT the model does not know degrades to raw hex, never a failure.
- With a keyring, a secured group telegram is verified and decrypted with the group key of its destination GA, decoded like a plain one and marked `[secured]`.
- A MAC failure shows `[secured (MAC failed) seq=… raw=…]`, and a GA without a key shows `[secured (no group key) …]`.
- A sequence number that does not increase per sender adds a warning. Nothing is dropped.

??? note "Details"
    A secured group telegram is `A_SecureData` with the tool-access bit clear.

## `bussard capture --to <DB>`

Capture telegrams to a SQLite database. The schema is on [JSON output](../json-output.md).

```console
$ bussard capture --to <DB> [--filter <EXPR>] [--keyring <FILE>]
```

| Flag | Default | Meaning |
|---|---|---|
| `--to <DB>` | required | The database file to write; created if absent. |
| `--filter <EXPR>` | all | Only capture matching telegrams. |
| `--keyring <FILE>` | the key store | As for `monitor`: secured group telegrams are decrypted into the decoded snapshot, which carries the `secured` fields. The raw cEMI frame keeps the secured bytes. |

## `bussard read <GA>`

Send a GroupValueRead for one group address and print the typed response.

```console
$ bussard read 3/2/0
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `<GA>` | | The group address to read, e.g. `3/2/0`. |
| `--keyring <FILE>` | the key store | Group keys for secured GAs. The password comes from `BUSSARD_KEYRING_PASSWORD`. |
| `--json` | off | Print `{"schema", "ga", "name", "answered", "value", "dpt", "raw", "source", "secured"}`. Without an answer `answered` is `false`. A secured read that timed out adds `reason`; one refused for sender admission has `sent: false`, `admission: "refused"`, `error` and `hint`. |

Behaviour:

- Exits non-zero when no response arrives within 3 seconds, in text and JSON mode.
- A GA with a group key, or with `secure = true` in `groups.toml`, is read with a secured GroupValueRead. Only a response whose MAC verifies under the group key is accepted, and stderr says `secured: …`.
- A secured GA without a key is refused before anything is sent.
- Before a secured read, bussard checks that the responder admits its tunnel address (see [sender admission](#sender-admission-on-a-secured-ga)).
- A secured read that times out says that a timeout usually means the responder does not admit the sender.

### Sender admission on a secured GA

A KNX Data Secure device accepts a secured telegram only from an address in its security individual address table, the list of senders it trusts. `read` and `write` check that list before sending from the tunnel address the gateway assigned.

| Evidence for each device the model links to the GA | Verdict |
|---|---|
| The device's recorded table (`secure_senders` in `bussard.lock`, from `bussard adopt` or a verified secured `apply`, `apply --line`, `flash` or `knx_apply_device`) | Admits exactly the addresses it lists. |
| No recorded table, but an ETS assignment of the GA to that tunnelling address in the keyring or key store | Admitted. |
| Neither | Unknown. |

When every linked device has a recorded table that lacks the tunnel address, the command is refused before sending:

```console
1.1.5 does not list the tunnel address 1.1.25 as a secure sender of 1/0/4; the actuator would discard the telegram. Admit the tunnel addresses (see below) or send plain only if the GA is not secured on the device.
```

The refusal is followed by how to admit them. With no evidence either way, the telegram is sent and stderr says:

```console
note: sent secured from 1.1.25; delivery to 1.1.5 is not confirmed by KNX; if nothing happens, 1.1.5 probably does not admit 1.1.25
```

To admit the tunnel addresses, set `admit_tunnel_senders = true` under `[connection]` and `apply` the device. The other ways are on [KNX Secure](../../how-to/knx-secure.md).

## `bussard write <GA> <VALUE>`

Write one group value to the bus, encoded against the GA's DPT from `groups.toml`. Nothing is stored on a device, but actuators move.

!!! warning
    `write` transmits on the bus. Check the gateway the prompt names.

```console
$ bussard write 3/0/4 on
```

The value is human-typed: `on`/`off`, `up`/`down`, a number, or a percentage like `75%`.
A scene number is the raw field, 0 to 63. ETS and Home Assistant show scenes counted from
1 (KNX 03_07_02 Datapoint Types §3.19 NOTE 9), so ETS scene 4 is `scene 3` here (#495).

| Flag / arg | Default | Meaning |
|---|---|---|
| `<GA>` | | The group address to write, e.g. `3/0/4`. |
| `<VALUE>` | | The value to encode. |
| `--dpt <DPT>` | the GA's DPT | The DPT to encode as. |
| `--force` | off | Override the protected-group-address refusal: write to a GA marked `protected = true` in `groups.toml`. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--json` | off | Print `{"schema", "ga", "name", "value", "dpt", "payload", "secured", "gateway", "confirmed", "result", "admission", "note"}` after the write. `result` is what KNX confirmed; `admission` is `admitted`, `unknown` or `null` (a plain GA); `note` is the unknown-delivery note. A write refused for sender admission prints `sent: false`, `admission: "refused"`, `reason` and `hint`. |
| `--keyring <FILE>` | the key store | Group keys for secured GAs. |

Behaviour:

- A non-loopback gateway needs `--allow-remote-gateway`; the gate is checked before the prompt.
- On a terminal it confirms, naming the GA, the decoded value and the resolved gateway. Without a terminal it refuses unless `--yes` is given.
- A GA marked `protected = true` is refused without `--force`.
- A GA with a group key, or `secure = true` in `groups.toml`, is written as a secured group telegram. A secured GA without a key is refused before anything is sent.
- A plain GA is sent byte for byte as without a keyring.
- A secured write is refused, or carries a note, as described under [sender admission](#sender-admission-on-a-secured-ga).
- The result line on stderr says only what KNX confirms: `the interface acknowledged the telegram (L_Data.con); KNX reports no application-level result`. A group write gets no reply from the device. When the confirmation is not seen in time the line says so, and the exit code stays 0.

??? note "Details"
    A secured group telegram uses SCF `0x10`, the group key and a sequence number above the last one sent. The receiver's list of trusted senders is the security individual address table (PID 54).

## `bussard learn`

Name and type group addresses from live traffic. `learn` prompts you to trigger an object, waits for the telegram, and proposes a name and DPT.

```console
$ bussard learn [--ga <GA>]... [--unnamed] [--untyped] [--timeout <SECS>] [--yes]
```

For each telegram it shows the sender, its channel and com object, the payload, ranked DPT candidates with a reason for each, and a name built from the device's room, channel and com-object function. You accept, edit the name, change the DPT, skip, or quit.

| Flag | Default | Meaning |
|---|---|---|
| `--ga <GA>` | | Learn this group address. Repeatable; learned in the order given. |
| `--unnamed` | off | Learn every GA in the model whose name is a placeholder (empty, the address itself, `GA <address>`, `Unnamed`, `Unknown...`). |
| `--untyped` | off | Learn every GA in the model with no DPT (the ones `validate` reports as W011). |
| `--yes` | off | Skip the confirmation prompt: accept the top candidate and the proposed name. Without a terminal the command is refused unless this is given. |
| `--timeout <SECS>` | `30` | How long to wait for each telegram. |
| `--keyring <FILE>` | the key store | ETS `.knxkeys` keyring whose group keys decrypt secured group telegrams. The password comes from `BUSSARD_KEYRING_PASSWORD`. |

Behaviour:

- `learn` never transmits. It listens on the same connection `monitor` uses.
- With neither `--ga` nor `--unnamed`/`--untyped`, it takes whatever appears on the bus next, one GA at a time, until a wait times out or you quit.
- Accepted answers go into `groups.toml`. When the sending com object can be pinned down (an existing link, or exactly one free transmit-capable object on the sending device), the sending device's file gets the `send` link too.
- A DPT candidate is ranked `high` only when the sending com object declares that DPT in the model. Payload shape alone gives `medium` at most, because most payload lengths fit several DPTs. Repeated telegrams on one GA narrow the candidates.
- With a keyring, a secured telegram is verified and decrypted as in `monitor --keyring`, and the inference runs on the decrypted value. The stdout line ends in `, secured)`, and the learned group gets `secure = true` in `groups.toml`, so `read`, `write`, `flash` and `apply` treat it as secured.
- A secured telegram that cannot be verified (no keyring, no group key for the GA, a MAC failure) is reported and skipped. `learn` never guesses a DPT from ciphertext.
- A sequence number that does not increase over the sender's last one prints the warning `monitor` shows.

## `bussard test`

Run the acceptance tests in `tests.toml` against the bus and print a pass/fail report. Each test writes a group value, or prints a `manual` instruction and waits for Enter, then waits for the expected telegram.

!!! warning
    `test` writes to the bus. It goes through the same rails as `bussard write`.

```console
$ bussard test [--file <FILE>] [--only <NAME>]... [--skip-manual] [--yes]
```

| Flag | Default | Meaning |
|---|---|---|
| `--file <FILE>` | `<dir>/tests.toml` | The test file to run. See [`tests.toml`](../files/tests-toml.md). |
| `--json` | off | Print the report as JSON: `started_at`, `tests[]` (`name`, `status` of `pass`/`fail`/`skipped`/`refused`, `detail`, `observed`) and `summary` counts. |
| `--force` | off | Override the protected-group-address refusal: write to a GA marked `protected = true` in `groups.toml`. The test also needs `allow_protected = true` in the test file. |
| `--skip-manual` | off | Report `manual:` tests as skipped instead of prompting. Without a terminal they are skipped anyway. |
| `--only <NAME>` | all | Run only the named test (case-insensitive). Repeatable. |
| `--yes` | off | Skip the confirmation prompt. Without a terminal the command is refused unless this is given. |
| `--secure-idle <SECS>` | | Instead of running `tests.toml`: measure the KNXnet/IP Secure session idle timeout. See [below](#measuring-the-secure-session-timeout). |

Behaviour:

- A non-loopback gateway needs `--allow-remote-gateway`, and the run confirms on a terminal naming the gateway.
- The keys serve the tunnel only.
- A test that writes to a `protected = true` GA needs both `allow_protected = true` in the file and `--force`. With either missing it is reported as `refused` and nothing is sent to that GA.
- A failing expectation reports the value that did arrive on the expected GA.
- Exits non-zero when any test fails. Skipped and refused tests do not fail the run.
- The text report has no timestamps, so two runs over a healthy installation are byte-identical. The JSON report adds only `started_at`.

### Measuring the secure session timeout

`bussard test --secure-idle <SECS>` opens a KNXnet/IP Secure session with the interface, sends nothing for `SECS` seconds, then checks whether the session is still alive. It prints one line:

| Result | Meaning |
|---|---|
| `ALIVE` | The interface answered. |
| `DROPPED after <t> s (<reason>)` | The interface ended the session or closed the connection. |
| `SILENT` | No answer. |

- The credentials come from `connection.keyring`, or from `--secure-user`/`--secure-password-env`. `--secure-transport` picks the carrier.
- `--json` prints the same as an object: `outcome`, `after_ms`, `reason`, `answered_ms`, `transport`, `user_id`.
- It uses no tunnel slot and nothing reaches the bus, so it needs neither `--yes` nor `--allow-remote-gateway`.
- Run it with growing `SECS` (say 45, 65, 90, 125) to bracket the interface's timeout.

??? note "Details"
    During the wait bussard sends no keepalive, no heartbeat and opens no tunnel (no CONNECT). Afterwards it sends one wrapped CONNECTIONSTATE_REQUEST for a channel it does not hold. `DROPPED` means the interface sent a SESSION_STATUS or closed the TCP connection.

## Related

- [Watch the bus](../../how-to/watch-the-bus.md): monitor, read and capture in practice.
- [JSON output](../json-output.md): the telegram JSON and the capture database.
- [Write commands](../../explanation/write-commands.md): the rails every write goes through.
- [KNX Secure](../../how-to/knx-secure.md): keyrings, secure tunnelling and secured group addresses.
