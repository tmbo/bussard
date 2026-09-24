# Working with an integrator

An owner and an integrator exchange changes to one installation in one of two ways. The file track is the default: the two sides send each other `.bussard` bundles or `.knxproj` files, the way integrators already hand over ETS projects on a USB stick. The repository track is for customers who want one shared git repository with pull requests and CI. Both tracks end the same way: a human on site runs `plan` and `apply`.

On both sides an assistant usually does the reading and writing over MCP, and the human decides. The examples show both what the assistant calls and the command a human would type.

## What never enters a bundle or a repository

| Never share | Why |
|---|---|
| `.knxproj` project files | Contain the full ETS project, often password-protected, and belong to whoever the contract says. |
| `.knxprod` vendor product files, `models/`, `vendor/` | The manufacturer's copyrighted application data ([product-data.md](product-data.md)). |
| `.knxkeys` keyrings and tool keys | The KNX Secure keys to every secured device. |
| Passwords, `.env` | The project password, keyring password, gateway credentials. |
| `captures/` | Bus recordings of a lived-in house. |

`bussard export` copies an allow-list of model files and nothing else, so a bundle cannot carry any of these by accident. A repository needs the ignore entries that `bussard init` writes. Send keyrings and passwords on a separate channel, or hand them over in person.

## The file track

The handover bundle is the delivered state. At acceptance the integrator exports it, and the model checksum from its manifest goes on the acceptance protocol next to the signatures ([handover checklist](handover-checklist.md)). From then on:

1. The owner's assistant exports the current model as a bundle (`knx_export_bundle`), or the owner describes the wish in words.
2. The integrator runs `bussard diff` between the delivered bundle and the one received. The output is the list of everything the owner changed since handover, in sentences. That is the warranty question answered before any work starts.
3. The integrator makes the change, in ETS or in bussard, and sends back a `.knxproj` or a bundle.
4. The owner's assistant previews the received file with `knx_diff_project` and reads the sentences back. The owner imports it with `bussard import`. Generated data follows the file; names, rooms and descriptions the owner wrote stay hers, and each disagreement is reported as a sentence.
5. Whoever is on site runs `plan` and `apply` for the devices that changed.

`bussard history` on either side shows who changed what, when, and which gateway each device write went to.

### Worked example: one link, by file

The example uses the four-device model in `knx-sim/examples/small-installation`, which points at the knx-sim gateway on `127.0.0.1:13671`. The outputs are illustrative: they follow the sentence style of the change renderer, but they were written by hand.

The owner wants the kitchen light command to switch the hallway light as well. She asks her assistant, which exports the model:

```text
Owner:      Send Jonas the house and ask him to make the kitchen switch
            also switch the hallway light.
Assistant:  (calls knx_export_bundle)
            Wrote knx-2026-10-01.bussard (4 devices, 7 group addresses).
            Attach it to your mail to Jonas.
```

The integrator first checks what changed since he delivered:

```console
$ bussard diff delivered-2026-06-01.bussard knx-2026-10-01.bussard
1 change(s) from delivered-2026-06-01.bussard to knx-2026-10-01.bussard:
  Group address 1/0/1 is now called "Kitchen ceiling" (was "Light Kitchen").
```

A rename, nothing that affects the warranty. He unpacks the bundle into an empty directory, which reproduces the owner's model byte for byte, history included, and adds the link:

```console
$ bussard import knx-2026-10-01.bussard --dir house
```

His assistant makes the edit with `knx_add_link` (device `1.0.3`, com object `1`, GA `1/0/1`, role `listen`). Before sending, he checks exactly what he is sending back:

```console
$ bussard diff knx-2026-10-01.bussard house
1 change(s) from knx-2026-10-01.bussard to house:
  Switch On/Off on Switch Hallway now listens to Kitchen ceiling (1/0/1).
$ bussard export house-2026-10-02.bussard --dir house
```

The owner's assistant reads the returned file before anything is imported:

```text
Owner:      Jonas sent house-2026-10-02.bussard. What does it change?
Assistant:  (calls knx_diff_project)
            One change: Switch On/Off on Switch Hallway now listens to
            Kitchen ceiling (1/0/1). No protected address is touched.
            To take it, run: bussard import house-2026-10-02.bussard
```

```console
$ bussard import house-2026-10-02.bussard
$ bussard plan 1.0.3
...
1 addition(s), 0 removal(s), 2 unchanged:
  + add:    object    1 → 1/0/1

run `bussard apply 1.0.3` to write these changes (with confirmation).
$ bussard apply 1.0.3
...
apply 1 change(s) to 1.0.3 via 127.0.0.1:13671? [y/N] y
backup written to knx/captures/backups/1.0.3-1790524800.json

apply verified: address table Loaded (3 entries), association table Loaded (3 entries)
```

The import snapshots the model first, so `bussard undo` reverts it. Against a real gateway, `apply` also needs `--allow-remote-gateway`.

Had the integrator worked in ETS instead, he would have sent a `.knxproj`. The owner's side is the same: `knx_diff_project` explains it, `bussard import house.knxproj` merges it. If the integrator renamed something the owner had also renamed, the import keeps her value, prints the disagreement and exits 3; `--theirs`, `--mine` or `--interactive` settles it.

## The repository track

For customers who already work with git, one repository per installation replaces the mail exchange:

1. The repository holds the model directory (`knx/`) and the ignore entries from `bussard init`. Nothing from the table above.
2. The owner's assistant makes the change on a branch with the model-edit tools and opens a pull request. The pull request description quotes the sentences from `knx_describe_change`.
3. CI checks the change without a bus.
4. The integrator reviews and approves. The sentences are the review; the TOML diff is there for whoever wants it.
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

`validate` runs the structural checks and, when `bussard.toml` has a `[lint]` table, the topology and convention lints (`L001` to `L008`). It exits non-zero on an error. `diff` prints the change in sentences into the job log.

`plan` reads the live device, so it cannot run in CI. The person on site runs `bussard plan --line 1.0 --json` before merge and attaches the output to the pull request, so the reviewer sees the device-level changes too.

### Worked example: one link, by pull request

The same change as above, in a repository holding `knx-sim/examples/small-installation/knx` as `knx/`:

```text
Owner:      Make the kitchen switch also switch the hallway light and
            open a pull request for Jonas.
Assistant:  (calls knx_add_link, then knx_describe_change)
            Switch On/Off on Switch Hallway now listens to Light Kitchen (1/0/1).
            (with its own git tools: commits knx/devices/*.toml on branch
            kitchen-hallway, opens the pull request with that sentence
            as its description)
```

CI prints:

```console
$ bussard validate --dir knx
0 errors, 0 warnings
$ bussard diff ../base/knx knx
1 change(s) from ../base/knx to knx:
  Switch On/Off on Switch Hallway now listens to Light Kitchen (1/0/1).
```

The on-site plan attached to the pull request:

```console
$ bussard plan 1.0.3 --json
```

It lists one addition, object 1 to `1/0/1`, on device `1.0.3`. The integrator approves, the pull request merges, and on site:

```console
$ git pull
$ bussard apply 1.0.3
...
apply 1 change(s) to 1.0.3 via 127.0.0.1:13671? [y/N] y
apply verified: address table Loaded (3 entries), association table Loaded (3 entries)
$ bussard test
```

`bussard test` runs the acceptance tests in `knx/tests.toml`; the fixture has none, so a real installation adds its own. bussard's own history records the `apply` alongside the git history, so `bussard history` still answers which gateway the write went to.
