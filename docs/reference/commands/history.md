# History commands

The commands that list, show and restore the project snapshots under `<dir>/.bussard/history`: `history`, `show` and `undo`. They read and write files only, never a device. Global options and exit codes are on [Global options](../global-options.md).

## `bussard history`

List the snapshots under `<dir>/.bussard/history`, oldest first.

```console
$ bussard history
```

Each line shows the number, the id, the command and arguments that caused the snapshot, the gateway a bus write went to, and a one-line summary of what it changed.

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Print `{"schema", "ok", "count", "snapshots": [...]}` (the object `knx_history` returns); each snapshot has `index`, `id`, `created_at`, `command`, `args`, `gateway`, `result` and `summary`. |

Behaviour:

- The output is deterministic apart from the timestamps.

## `bussard show <SNAPSHOT> [SNAPSHOT]`

Show what one snapshot changed against the one before it, or the change between two snapshots.

```console
$ bussard show 12
$ bussard show 10 12
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `<SNAPSHOT>` | | The snapshot to show: its id, or its number from `bussard history`. |
| `[SNAPSHOT]` | | A second snapshot: show the change from the first to this one. |
| `--json` | off | Print `{"schema", "ok", "from", "to", "reason", "count", "touches_protected", "sentences", "changes": [...]}`, the same change objects as `status --json` and the object `knx_describe_change` returns. |

## `bussard undo [SNAPSHOT]`

Restore the project files to a snapshot, print what that reverts, and point at `plan` and `apply`.

```console
$ bussard undo
```

| Flag / arg | Default | Meaning |
|---|---|---|
| `[SNAPSHOT]` | the newest one that differs from the working files | The snapshot to restore: its id or number. |
| `--json` | off | Print `{"schema", "ok", "restored", "created_at", "undo_snapshot", "changes": [...], "key_store"}`. `restored` is `null`, with a `reason`, when nothing was restored. `key_store` is `null` unless the undo changed a group address's Data Secure state: then `{"ok": true, "sentences"}`, or `{"ok": false, "reason"}` when the key store did not follow. |

Behaviour:

- Files only. Devices keep their tables until you push the restored project to them with `plan` and `apply`.
- bussard takes a snapshot before each write, so `undo` with no argument reverts exactly the last change, whether it was an edit to the project or a bus-only command like `apply`.
- The state before the undo is itself snapshotted, so a second `undo` reverts the first.
- An undo that flips a group address's Data Secure state also changes the key store: the group key comes back from the snapshot's copy, or leaves the store. It needs `BUSSARD_KEYRING_PASSWORD`.

## Related

- [Change a link](../../how-to/change-a-link.md): plan, apply and undo a change.
- [Assistant](../../explanation/assistant.md): history and undo when an assistant edits the project.
- [Project folder](../model-directory.md): where `.bussard/history` lives.
