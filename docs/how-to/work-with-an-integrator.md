# Work with an integrator

Exchange changes to one installation between an owner and an integrator. The file track is the default: both sides send each other `.bussard` bundles or `.knxproj` files, the way integrators already hand over ETS projects. The repository track is for customers who want one shared git repository with pull requests. Both end the same way: someone on site runs `plan` and `apply`.

On both sides an assistant usually does the reading and writing over MCP, and the human decides.

## Keep these out of every bundle and repository

| Never share | Why |
|---|---|
| `.knxproj` project files | The full ETS project, often password-protected, owned by whoever the contract says. |
| `.knxprod` vendor product files, `products/` (unless the repository is private), `.bussard/` | The manufacturer's copyrighted application data. |
| `.knxkeys` keyrings and tool keys | The KNX Secure keys to every secured device. |
| Passwords, `.env` | The project password, keyring password, gateway credentials. |
| `captures/` | Bus recordings of a lived-in house. |

`bussard export` copies an allow-list of model files and nothing else, so a bundle cannot carry any of these by accident. A repository needs the ignore entries that `bussard init` writes. Send keyrings and passwords on a separate channel, or in person.

## Exchange files

The handover bundle is the delivered state. At acceptance the integrator exports it, and the model checksum from its manifest goes on the acceptance protocol ([handover checklist](handover-checklist.md)). From then on:

1. The owner exports the current model (`bussard export`, or `knx_export_bundle` over MCP), or describes the wish in words.
2. The integrator runs `bussard diff` between the delivered bundle and the one received. That lists, in sentences, everything the owner changed since handover: the warranty question, answered before work starts.
3. The integrator makes the change, in ETS or in bussard, and sends back a `.knxproj` or a bundle.
4. The owner previews the file (`bussard diff`, or `knx_diff_project`) and imports it with `bussard import`. Names, rooms and descriptions the owner wrote stay hers; each disagreement is reported as a sentence.
5. Whoever is on site runs `plan` and `apply` for the devices that changed.

`bussard history` on either side shows who changed what, when, and which gateway each device write went to.

### Example: one link, by file

This uses the four-device model in `knx-sim/examples/small-installation`, which points at the simulator on `127.0.0.1:13671`. The outputs are illustrative.

The owner wants the kitchen switch to switch the hallway light too. Her assistant exports the model as `knx-2026-10-01.bussard`. The integrator first checks what changed since he delivered:

```console
$ bussard diff delivered-2026-06-01.bussard knx-2026-10-01.bussard
1 change(s) from delivered-2026-06-01.bussard to knx-2026-10-01.bussard:
  Group address 1/0/1 is now called "Kitchen ceiling" (was "Light Kitchen").
```

A rename, nothing that affects the warranty. He imports the bundle into an empty directory, which reproduces her model byte for byte, history included:

```console
$ bussard import knx-2026-10-01.bussard --dir house
```

His assistant adds the link with `knx_add_link` (device `1.0.3`, com object `1`, group address `1/0/1`, role `listen`). Before sending, he checks what he sends back:

```console
$ bussard diff knx-2026-10-01.bussard house
1 change(s) from knx-2026-10-01.bussard to house:
  Switch On/Off on Switch Hallway now listens to Kitchen ceiling (1/0/1).
$ bussard export house-2026-10-02.bussard --dir house
```

The owner's assistant reads the returned file with `knx_diff_project` and reports the same sentence, and that no protected address is touched. She imports it and plans the device:

```console
$ bussard import house-2026-10-02.bussard
$ bussard plan 1.0.3
1.0.3 Switch actuator
  channel a (Hallway)
    + switch now listens on 1/0/1 (Hallway light)
  unchanged: 2 objects
  writes: address table (3 entries), association table (3 entries)
  backup: knx/captures/backups
```

!!! warning
    `apply` writes the device's tables. Against a real gateway it also needs `--allow-remote-gateway`.

```console
$ bussard apply 1.0.3
...
apply this change to 1.0.3 through 127.0.0.1:13671? [y/N] y
backup written to knx/captures/backups/1.0.3-1790524800.json

apply verified: address table Loaded (3 entries), association table Loaded (3 entries)
```

The import snapshots the model first, so `bussard undo` reverts it. Had the integrator worked in ETS, he would have sent a `.knxproj`; the owner's side is the same. If both renamed the same thing, the import keeps her value, prints the disagreement and exits 3; `--theirs`, `--mine` or `--interactive` settles it.

## Share a repository

For customers who already use git, one repository per installation replaces the mail:

1. The repository holds the model directory (`knx/`) and the ignore entries from `bussard init`, and nothing from the table above.
2. The owner's assistant makes the change on a branch and opens a pull request quoting the sentences from `knx_describe_change`.
3. CI checks the change without a bus.
4. The integrator reviews the sentences and approves.
5. After merge, whoever is on site pulls, runs `plan` and `apply`, then `bussard test` to rerun the acceptance tests.

A CI job for step 3:

```yaml
jobs:
  model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: curl -fsSL https://raw.githubusercontent.com/tmbo/bussard/main/install.sh | sh
      - run: bussard validate --dir knx
      - run: |
          git worktree add ../base origin/${{ github.base_ref }}
          bussard diff ../base/knx knx
```

`validate` exits non-zero on an error and, when `bussard.toml` has a `[lint]` table, also checks the topology and address conventions. `diff` prints the change in sentences into the job log. `plan` reads the live device, so it cannot run in CI: the person on site runs `bussard plan --line 1.0 --json` before merge and attaches the output to the pull request.

## Next steps

- [Handover checklist](handover-checklist.md): what to deliver at acceptance.
- [Exchange with ETS](exchange-with-ets.md): get names into ETS and read a new export.
- [Model directory](../reference/model-directory.md): what a bundle contains.
