# bussard documentation

bussard is an open-source command line tool for a KNX building bus. It keeps your installation as a folder of plain text files, your bussard project, and writes that project to the devices over a KNXnet/IP gateway. It decodes everything on the bus with the same project, and runs as an MCP server so an LLM assistant can read and edit the project with you.

It is for the owner of a KNX house who wants to know what every button does, change one safely and undo it, and for the integrator who needs the exact command, its flags and what it refuses. See the [landing page](../) for the overview and the [GitHub repository](https://github.com/tmbo/bussard) for the source.

## Talk to your house

You say what you want in chat, and an assistant such as Claude runs bussard for you over MCP. Start here if you own the house and would rather not learn commands.

1. [Install bussard](getting-started/install.md).
2. [Connect an assistant](getting-started/assistant.md) on an empty folder and say "set up my house": it finds the gateway and imports your ETS export, if you have one.
3. [The first weekend](getting-started/first-weekend.md): an audit, a backup of every device, one change and its undo.

## Work at the terminal

You type the commands yourself and read their output. Start here if you are an integrator, or want the exact command and its flags.

1. [Install bussard](getting-started/install.md).
2. [Your first project](getting-started/first-model.md): `bussard import` turns an ETS project export (`.knxproj`) into a bussard project in a minute; without one, `bussard init` creates an empty project and you scan, reconstruct or adopt the devices you have.
3. The [how-to guides](how-to/index.md), one task each.

Every guide shows both forms, in chat and at the terminal. Read [Safety](explanation/safety.md) before your first write.

## Getting started

- [Install bussard](getting-started/install.md): installers, the binary and its checksum, building from source.
- [Your first project](getting-started/first-model.md): import or init, validate, monitor.
- [Connect an assistant](getting-started/assistant.md): an LLM over MCP and a first conversation.
- [The first weekend](getting-started/first-weekend.md): an owner's path from install to a backup on a USB stick.

## How-to guides

- [Watch the bus](how-to/watch-the-bus.md): monitor, read, the browser view, capture and history.
- [Find what you have](how-to/find-what-you-have.md): audit, scan, describe, reconstruct, free tunnel slots.
- [Change what a button does](how-to/change-a-link.md): plan, apply and undo a link change.
- [Change a parameter](how-to/change-a-parameter.md): the device dialog, then apply or flash.
- [Add a device](how-to/add-a-device.md): adopt, flash a fresh device, label on the bench.
- [Back up and replace a device](how-to/back-up-and-replace.md): backup, restore, replace a dead device.
- [Commission a line](how-to/commission-a-line.md): plan group addresses, commission, test.
- [Exchange with ETS](how-to/exchange-with-ets.md): names into ETS, what a new export changes.
- [Work with an integrator](how-to/work-with-an-integrator.md): bundles and shared repositories.
- [Home Assistant](how-to/home-assistant.md): generate and tune the Home Assistant config.
- [KNX Secure](how-to/knx-secure.md): the key store, secure tunnelling, secure a group address.

## Reference

- [Commands](reference/index.md): every command by group, with its flags, refusals and verification steps.
- [Global options](reference/global-options.md) and [environment variables](reference/environment.md): what every command shares, exit codes, the `.env` file.
- [The project folder](reference/model-directory.md) and its [files](reference/files/device-files.md): every file and key, the lock, the key store, parse errors.
- [Diagnostics](reference/diagnostics.md), [product data](reference/product-data.md), [JSON output](reference/json-output.md), [MCP tools](reference/mcp-tools.md), [viz API](reference/viz-api.md), [Home Assistant](reference/home-assistant.md).

## Explanation

- [How bussard works](explanation/how-it-works.md): the project, product data, the bus and a write.
- [Safety](explanation/safety.md): the rules, on one page, to read before the first write.
- [Write commands](explanation/write-commands.md): what each write command does and its rails.
- [KNX Secure](explanation/knx-secure.md): keys, the key store, secrets, what secured means.
- [The assistant](explanation/assistant.md): MCP tiers, history and undo, protected addresses.
- [Device support](explanation/device-support.md): supported devices, the tunnel budget, known limits.
