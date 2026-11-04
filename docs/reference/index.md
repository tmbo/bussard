# Reference

Every command, flag, file and key, stated once. The pages are grouped by what
they describe.

**The command line**

- [Global options](global-options.md): options every command takes, confirmation and JSON, exit codes.
- [Environment variables](environment.md): the `BUSSARD_*` variables and the `.env` file.
- Commands: [project](commands/model.md), [bus](commands/bus.md), [devices](commands/devices.md), [programming](commands/programming.md), [KNX Secure](commands/secure.md), [history](commands/history.md), [servers](commands/servers.md).

**The project folder**

- [The project folder](model-directory.md): how bussard finds it, what `products/` and `.bussard/` hold, the bundle format.
- Files: [bussard.toml](files/bussard-toml.md), [groups.toml](files/groups-toml.md), [device files](files/device-files.md), [bussard.lock](files/bussard-lock.md), [bussard.keys](files/bussard-keys.md), [tests.toml](files/tests-toml.md), [ha.toml](files/ha-toml.md), [errors](files/errors.md).
- [Validation diagnostics](diagnostics.md): every code `validate` reports.
- [Product data](product-data.md): `.knxprod` files, the product store, the pointer index.

**Interfaces**

- [JSON output](json-output.md): the telegram JSON contract and the capture database.
- [MCP tools](mcp-tools.md): what the MCP server exposes to an assistant, by tier.
- [viz API](viz-api.md): the endpoints of the browser view.
- [Home Assistant](home-assistant.md): how `ha-config` derives entities.
