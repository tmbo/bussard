# The first weekend

This tutorial is for the owner of a KNX house who wants to understand it, back it up and change it without an integrator. By Sunday evening your house is a named model on your laptop, every device is backed up, you have made one change and undone it, and a copy of the whole configuration sits on a USB stick in the cabinet.

An assistant does most of the work. bussard runs as an MCP server, so an assistant such as Claude reads the model, watches the bus, answers questions and proposes changes. You type the commands that program devices, because those need a hand on the keyboard and a look at the confirmation. Each step names the safety rail that protects it; [Safety](../explanation/safety.md) explains them all in one place.

## What to have ready

- A KNXnet/IP interface or router in the cabinet, and its IP address. Many houses from the 2010s have only a USB interface; an IP interface is then the first purchase.
- A laptop on the same network as the interface.
- An assistant that speaks MCP: Claude Code, Claude Desktop, or any other MCP client.
- Whatever the previous owner or integrator handed over: the `.knxproj` project file and its password, and the `.knxkeys` keyring for KNX Secure devices. [The handover checklist](../how-to/handover-checklist.md) lists what to ask for. A house with no project file works too; it takes longer.

## Step 1. Install bussard

On macOS or Linux with Homebrew, run `brew install tmbo/tap/bussard`. Without Homebrew, or on Windows, use an installer from [Install bussard](install.md); it downloads the binary and checks its checksum. `bussard --version` confirms it is on your `PATH`.

## Step 2. Create the model

```console
$ mkdir house && cd house
$ bussard init
Searching for KNXnet/IP gateways on the local network...
Found gateway: IP Interface (192.0.2.10:3671, IA 1.1.250, 4 tunnels, 1 in use)

Created a fresh KNX model in the current directory /Users/nadia/house.
```

`init` finds the interface, writes its address into `bussard.toml` and creates an empty model in the current directory. In a directory that already holds other files it asks first. Every later command finds the model from this directory or any directory below it, so there is no `--dir` to remember. If discovery finds nothing, pass the address: `bussard init --gateway 192.0.2.10`.

Keep passwords in a `.env` file here, for example `BUSSARD_PROJECT_PASSWORD=...`. bussard reads it automatically, and the `.gitignore` that `init` writes already lists `.env`. `BUSSARD_ALLOW_REAL_GATEWAY` is never taken from it: arming writes to the real bus stays a flag or an exported variable.

The tunnel count matters. An interface has a fixed number of connection slots, often one to five. Home Assistant holds one permanently, ETS holds one while a project is online, and every running bussard command holds one, including the assistant's server. "4 tunnels, 1 in use" leaves room for the assistant and a command at the same time. With a one-tunnel interface and Home Assistant running, bussard gets no slot; it says so and exits with code 4 instead of hanging. [Device support](../explanation/device-support.md) explains the tunnel budget.

Safety rail: `init` only reads from the network.

## Step 3. Connect the assistant

For Claude Code, run this once in the model directory:

```console
$ claude mcp add knx -- bussard mcp --dir "$PWD"
```

The client starts the server itself. Run `bussard mcp` by hand and it prints this command and a JSON entry for Claude Desktop and other clients, with your binary's full path, ready to paste. [Connect an assistant](assistant.md) has the JSON form and the Claude Desktop steps.

The default server reads the model, watches the bus, sends rate-limited read requests, and edits the model files. It cannot program a device and cannot write a value to the bus.

Safety rails: every model edit the assistant makes is saved to the history first and comes back as a plain sentence for the assistant to quote. Group addresses marked `protected = true` cannot be changed or linked over MCP at all. Device programming (`plan`, `apply`, `flash`) is on the command line; the server can write one device's link tables and parameters only when you start it with `--allow-programming` and approve the plan.

## Saturday morning: how good is my project file?

First get the installation into the model. With a project file, run `bussard import house.knxproj`. bussard takes the project password from `BUSSARD_PROJECT_PASSWORD` (the `.env` works) or asks for it.

Without one, find the devices and read back what they carry. `reconstruct` writes a new model directory, because it never merges into an existing one:

```console
$ bussard scan 1.1
$ bussard reconstruct --line 1.1 --out ../house-read
$ cd ../house-read
```

Then point the assistant at the new directory (`claude mcp remove knx`, then `claude mcp add knx -- bussard mcp --dir "$PWD"`) and work from there. A house with several lines needs one scan per line.

Now ask:

```text
You:        How good is my project file?
Assistant:  (calls knx_audit)
            The project has 72 devices on two lines and 318 group addresses.
            bussard can plan and apply 64 of the devices; 8 older ones
            (mask 0012) can only be inspected, so links on those stay with ETS.
            41 group addresses have no data type, and 3 devices have no room.
            Two addresses have a sender but nobody listening: 2/1/7 "Terrace
            blind wind" and 0/0/9. The weather station and 2 actuators are KNX
            Secure devices.
            Shall we fill in the missing types first?
```

The mask is the device's system type, which decides what bussard can do with it. `knx_audit` is the MCP form of `bussard audit`; run that in a terminal for the same report. With `live: true` the audit also asks the interface for its tunnel slots and summarises the traffic the server has seen.

Protect the safety functions before anything else. Ask the assistant which addresses look like the wind alarm, rain alarm or central off. It cannot set the flag itself, by design, so add it by hand in `groups.toml`, on the line of each such address:

```toml
  { address = "2/1/0", name = "Wind alarm", dpt = "1.005", protected = true },
```

Safety rails: the audit only reads. A protected address is refused by every MCP tool and needs `--force` on the command line.

## Saturday afternoon: name the house without a project file

A reconstructed model has placeholder names and no data types. The learn loop fixes that one button at a time, in chat:

```text
You:        Help me name the group addresses.
Assistant:  Press a button you know, then tell me which one it was.
You:        The left rocker by the front door.
Assistant:  (calls knx_wait_for_telegram, then knx_infer_group)
            Device 1.1.12 sent "on" to 1/1/1. Its com object 0 is a 1-bit
            switch, so the type is 1.001 (switch), high confidence.
            I would call it "Hallway light". OK?
You:        Yes, and the device is the hallway push button.
Assistant:  (calls knx_set_group, knx_add_link, knx_set_device)
            New group address Hallway light (1/1/1), type 1.001.
            Hallway push button now switches Hallway light (1/1/1).
```

Every telegram on an address narrows the type candidates, so an uncertain one gets "press it again". `bussard learn` runs the same loop in a terminal. A house with a project file can skip this step, or use it for the 41 untyped addresses with `bussard learn --untyped`.

Safety rails: learning only listens and never transmits. Each confirmed name is a separate history entry, so a wrong answer is one undo away.

## Saturday evening: take a full backup

Before the first change, read every device's tables into a backup:

```console
$ bussard backup
backing up 72 device(s) via 192.0.2.10:3671 into captures/backups/20260926T180000Z
...
64 backed up, 8 skipped, 0 unreachable, 0 failed
```

Skipped devices are the ones whose mask bussard cannot read. The backup holds each device's address and association tables and, on System B devices, the parameters. `bussard restore <backup-dir> <address>` writes one device back from it.

Safety rail: `backup` sends only read requests, so it is safe on a live house.

## Sunday morning: look around

`bussard viz` serves the whole installation as a web page on `http://127.0.0.1:8080`: devices by line, rooms, group addresses, live traffic, and a Problems panel.

`bussard doc --format html --out house-manual` writes the house manual the KNX guidelines ask for: a device list, a group address list with types, and one sheet per room with a sentence for every button and channel. Print the room sheets for the family. The assistant answers the rest ("what does the second rocker in the kitchen do?") from the model.

Safety rails: `doc` never touches the bus. `viz` without flags is a viewer and cannot write.

## Sunday afternoon: the first change

Ask for what the house should do. The assistant turns it into model edits and reads them back:

```text
You:        The hallway button should also switch the porch light.
Assistant:  (calls knx_model_lookup, then knx_add_link)
            Outdoor switch actuator, channel C, now listens to
            Hallway light (1/1/1).
            This changes the model only. To program the actuator, run
                bussard plan 1.1.7
                bussard apply 1.1.7 --allow-remote-gateway
```

The model now says what the house should do; the actuator does not know yet. `bussard status` shows every pending change in the same sentences. Look at what programming the actuator would change (the output is illustrative):

```console
$ bussard plan 1.1.7
1.1.7 Outdoor switch actuator
  channel c (Porch light)
    + schalten now listens on 1/1/1 (Hallway light)
  unchanged: 5 objects
  writes: address table (6 entries), association table (6 entries)
  backup: captures/backups
```

!!! warning
    `apply` writes the device. The confirmation names the gateway; read it before you type `y`.

```console
$ bussard apply 1.1.7 --allow-remote-gateway
...
apply this change to 1.1.7 through 192.0.2.10:3671? [y/N] y
backup written to captures/backups/1.1.7-1790445600.json

apply verified: address table Loaded (6 entries), association table Loaded (6 entries)
```

Press the hallway button. The porch light follows.

Safety rails: `plan` only reads. `apply` refuses a gateway that is not on this laptop unless you pass `--allow-remote-gateway`, because the most dangerous mistake is writing to the wrong bus. `apply` backs up the device's tables first and reads them back after writing. The assistant's server holds one tunnel while it runs, so `apply` needs a second free one.

## Monday: undo it

The porch light at 2 a.m. was a bad idea.

```text
You:        Undo the porch light change.
Assistant:  (calls knx_undo)
            Outdoor switch actuator, channel C, no longer listens to
            Hallway light (1/1/1).
            The model is back. Run plan and apply on 1.1.7 to program it.
```

`bussard undo` does the same from a terminal. Undo restores the model files only, so the device keeps the change until you program it again with `bussard plan 1.1.7` and `bussard apply 1.1.7 --allow-remote-gateway`.

`bussard history` lists every saved state with the command that caused it, and `bussard show <n>` explains one of them in sentences. The undo itself is saved too, so undoing an undo works.

Safety rail: bussard saves the model before every write, whether the writer is the assistant, an import or an `apply`. Nothing is lost by trying something.

## Last step: a copy on a USB stick

Write the model and its history into one file:

```console
$ bussard export /Volumes/USB/house.bussard
exported 72 device(s), 318 group address(es), 14 history snapshot(s) → /Volumes/USB/house.bussard
model sha256 3f1c…
```

The `.bussard` file holds the model, the history and a checksum of the model. It never holds the `.knxproj`, the `.knxkeys` keyring, vendor product files or passwords; keep those next to it on the stick, or in a password manager. Put the stick in the cabinet with the handover papers. After every `apply`, bussard reminds you when the last export is older than the model you just programmed.

`bussard import house.bussard` in an empty directory on a new laptop brings everything back, history included. The same file is what you send to an integrator; [Work with an integrator](../how-to/work-with-an-integrator.md) describes that exchange.

!!! note "For git users"
    bussard does not need git, but the model directory is git-friendly. Commit `bussard.toml`, `groups.toml`, `devices/`, `bussard.lock` and `tests.toml`, and let the generated ignore file keep the rest local. [Work with an integrator](../how-to/work-with-an-integrator.md) shows how an owner and an integrator share one repository.

## Next steps

- [Change what a button does](../how-to/change-a-link.md): the next link change, from plan to undo.
- [Back up and replace a device](../how-to/back-up-and-replace.md): restore a device or swap a dead one.
- [Find what you have](../how-to/find-what-you-have.md): audit, scan and reconstruct in detail.
- [Safety](../explanation/safety.md): every rail around a write, on one page.
