# The first weekend

This tutorial is for the owner of a KNX house who wants to understand it, back it up and change it without an integrator. By Sunday evening your house is a bussard project on your laptop, every device is backed up, you have made one change and undone it, and a copy of everything sits on a USB stick in the cabinet.

An assistant such as Claude does the work: bussard runs as an MCP server, and the assistant reads your project, watches the bus and proposes changes. You say yes at each step. Every write is protected by a rail; [Safety](../explanation/safety.md) lists them on one page, and this tutorial names the one that matters at each step.

## What to have ready

- A KNXnet/IP interface or router in the cabinet. A house with only a USB interface needs an IP interface first.
- A laptop on the same network as the interface.
- An assistant that speaks MCP: Claude Code, Claude Desktop, or any other MCP client.
- Whatever the previous owner or integrator handed over: the `.knxproj` project file and its password, and the `.knxkeys` keyring for KNX Secure devices. A house without a project file works too; it takes longer.

## Step 1. Install bussard

Use an installer from [Install bussard](install.md). `bussard --version` in a terminal confirms it is on your `PATH`. That is the last terminal command this weekend.

## Step 2. Connect the assistant and set up the project

Register the server on an empty folder, as [Connect an assistant](assistant.md) shows, put the project file next to it, and ask:

```text
You:        Set up my house. The ETS export is house.knxproj.
Assistant:  May I download the vendor product data the export lacks?
You:        Yes.
Assistant:  (calls knx_setup)
            Found the KNX IP Interface at 192.0.2.10. Imported 318 group
            addresses, 72 devices and 540 links.
```

The project file is usually password-protected: bussard opens a password form in your browser and stores the password in a `.env` file next to the project folder. The assistant never sees it. Without a project file, say "Set up my house. I have no ETS project." and the assistant creates an empty project; [Find what you have](../how-to/find-what-you-have.md) shows how to scan the line and read the devices into it.

Rail: setup only reads from the network.

## Saturday morning: how good is my project?

```text
You:        How good is my project?
Assistant:  (calls knx_audit)
            72 devices on two lines and 318 group addresses. bussard can
            plan and program 64 of the devices; 8 older ones can only be
            inspected. 41 group addresses have no data type and 3 devices
            have no room. Two addresses have a sender but nobody listening.
            The weather station and 2 actuators are KNX Secure devices.
            Shall we fill in the missing types first?
```

Before anything else, protect the safety functions. Ask the assistant which addresses look like the wind alarm, rain alarm or central off. It cannot set the flag itself, by design: add `protected = true` on the line of each such address in `groups.toml`.

```toml
  { address = "2/1/0", name = "Wind alarm", dpt = "1.005", protected = true },
```

Rail: the audit only reads. A protected address is refused by every MCP tool.

## Saturday afternoon: name what has no name

A project without a file, or with untyped addresses, gets its names one button press at a time:

```text
You:        Help me name the group addresses.
Assistant:  Press a button you know, then tell me which one it was.
You:        The left rocker by the front door.
Assistant:  (calls knx_wait_for_telegram, then knx_infer_group)
            Device 1.1.12 sent "on" to 1/1/1. The type is 1.001 (switch),
            high confidence. I would call it "Hallway light". OK?
You:        Yes, and the device is the hallway push button.
Assistant:  (calls knx_set_group, knx_add_link, knx_set_device)
            Hallway push button now switches Hallway light.
```

[Watch the bus](../how-to/watch-the-bus.md#name-group-addresses-from-live-traffic) has the details. A house with a good project file skips this step.

Rail: learning only listens. Each confirmed name is one undo away.

## Saturday evening: back up every device

```text
You:        Back up every device.
Assistant:  (calls knx_backup_device)
            64 devices backed up into captures/backups/20260926T180000Z,
            8 skipped because bussard cannot read their type.
```

The backup holds each device's tables and, where the device supports it, its parameters. [Back up and replace a device](../how-to/back-up-and-replace.md) shows how to restore one from it.

Rail: a backup sends only read requests.

## Sunday morning: look around

```text
You:        Show me the house in the browser.
Assistant:  (calls knx_viz)
            Open http://127.0.0.1:52133. The page shows every device by
            floor and room, the group addresses, live traffic and a
            problems panel.
You:        Write the house manual.
Assistant:  (calls knx_export)
            Written house-manual/: the device list, the group addresses
            with their types, and one sheet per room with a sentence for
            every button and channel.
```

Print the room sheets for the family. Everything else ("what does the second rocker in the kitchen do?") the assistant answers from the project. [Watch the bus](../how-to/watch-the-bus.md#see-the-installation-in-a-browser) shows the page.

Rail: both only read the project. The page cannot write.

## Sunday afternoon: the first change

Start the server with `--allow-programming` for this step, as [Connect an assistant](assistant.md#what-the-default-server-can-do) describes. Then ask for what the house should do:

```text
You:        The hallway button should also switch the porch light.
Assistant:  (calls knx_add_link)
            Outdoor switch actuator, channel C, now listens to Hallway
            light. The actuator does not know yet. Shall I show the plan?
You:        Yes.
Assistant:  (calls knx_plan_device)
            Programming 1.1.7 Outdoor switch actuator through 192.0.2.10
            writes its address table and association table, 6 entries each.
            Channel C gains Hallway light; 5 objects stay as they are.
            A backup is taken first. Go ahead?
You:        Yes.
Assistant:  (calls knx_apply_device)
            Programmed and read back: both tables match the project.
```

Press the hallway button. The porch light follows. [Change what a button does](../how-to/change-a-link.md) has the terminal form.

!!! warning
    The plan names the gateway. Read it before you say yes: the most dangerous mistake is writing to the wrong bus.

Rails: the plan only reads. Programming backs up the device first and reads it back after writing. A gateway that is not on your laptop needs `--allow-remote-gateway` on the server.

## Monday: undo it

The porch light at 2 a.m. was a bad idea.

```text
You:        Undo the porch light change.
Assistant:  (calls knx_undo)
            Outdoor switch actuator, channel C, no longer listens to
            Hallway light. The project is back; the actuator keeps the
            change until I program it again. Shall I?
You:        Yes.
```

Undo restores the project files only, so the device needs programming again. Every saved state stays in the history, the undo included, so undoing an undo works too.

Rail: bussard saves the project before every change, whoever makes it.

## Last step: a copy on a USB stick

```text
You:        Export my project to the USB stick at /Volumes/USB.
Assistant:  (calls knx_export)
            Written /Volumes/USB/house.bussard: 72 devices, 318 group
            addresses, 14 saved states.
```

The `.bussard` file holds the project and its history. It never holds the `.knxproj`, the `.knxkeys` keyring or passwords: keep those next to it on the stick, or in a password manager. Put the stick in the cabinet with the handover papers. The same file brings everything back on a new laptop, and is what you send to an integrator ([Work with an integrator](../how-to/work-with-an-integrator.md)).

## Next steps

- [Change what a button does](../how-to/change-a-link.md): the next link change, from plan to undo.
- [Back up and replace a device](../how-to/back-up-and-replace.md): restore a device or swap a dead one.
- [Find what you have](../how-to/find-what-you-have.md): audit, scan and reconstruct in detail.
- [Safety](../explanation/safety.md): every rail around a write, on one page.
