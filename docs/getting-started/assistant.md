# Connect an assistant

bussard runs as an MCP server, so an LLM assistant such as Claude can read your project, watch the bus and edit its files with you. This page connects one and walks through a first conversation.

You need a bussard project ([Your first project](first-model.md)) and an assistant that speaks MCP: Claude Code, Claude Desktop, or any other MCP client.

No project yet? Register the server on an empty folder (`--dir` names a folder that is empty or does not exist yet) and say "set up my house". The server starts with one tool, `knx_setup`: it finds the gateway, creates the project in that folder and imports your ETS export, as `bussard init` does. Put the `.knxproj` next to the folder or tell the assistant where it is. Afterwards the server offers its full tool set in the same conversation.

## Register the server

The server talks over stdin and stdout, so the client starts it; there is nothing to connect to. Each client takes one entry that names the binary and the project folder. Use absolute paths, because the client may start the server from any directory. The entry never holds a password.

=== "Claude Code"

    Put a `.mcp.json` next to the project folder, or in it:

    ```json
    {
      "mcpServers": {
        "knx": {
          "command": "bussard",
          "args": ["mcp", "--dir", "/Users/nadia/house"]
        }
      }
    }
    ```

    Claude Code reads it when you start a conversation in that folder and asks once whether to use the server. The tools appear in that conversation.

=== "Claude Desktop"

    Settings > Developer > Edit Config opens `claude_desktop_config.json` (on macOS in `~/Library/Application Support/Claude/`). Paste this entry, with the absolute path of your project folder, and restart Claude Desktop:

    ```json
    {
      "mcpServers": {
        "knx": {
          "command": "bussard",
          "args": ["mcp", "--dir", "/Users/nadia/house"]
        }
      }
    }
    ```

    The server shows under the tools icon in a chat, not in the connector list. The connector dialog takes the HTTPS URL of a remote server: bussard serves its tools over HTTP with `--listen`, behind a TLS front of your own, see [Over HTTP](../reference/commands/servers.md#over-http).

=== "Cursor"

    Settings > MCP > Add new global MCP server opens `~/.cursor/mcp.json`; a `.cursor/mcp.json` in the project does the same for one project. Paste this entry with the absolute path of your project folder:

    ```json
    {
      "mcpServers": {
        "knx": {
          "command": "bussard",
          "args": ["mcp", "--dir", "/Users/nadia/house"]
        }
      }
    }
    ```

=== "Codex CLI"

    Add this table to `~/.codex/config.toml`, with the absolute path of your project folder:

    ```toml
    [mcp_servers.knx]
    command = "bussard"
    args = ["mcp", "--dir", "/Users/nadia/house"]
    ```

=== "Other clients"

    Any client that starts a stdio MCP server takes a `mcpServers` entry of this shape:

    ```json
    {
      "mcpServers": {
        "knx": {
          "command": "/usr/local/bin/bussard",
          "args": ["mcp", "--dir", "/Users/nadia/house"]
        }
      }
    }
    ```

On macOS the first connection from a desktop client triggers the Local Network prompt: allow it, or the server cannot reach the interface and `knx_bus_status` says the operating system refused access to the local network. The permission belongs to the binary, so after you update bussard, allow it again (System Settings > Privacy & Security > Local Network) and restart the client.

The server reads the `.env` in or next to the project folder itself, so the passwords need not be in the client's config.

## What the default server can do

| The assistant can | The assistant cannot |
|---|---|
| read your project and answer "what do I have" | write a value to the bus |
| watch and decode live telegrams | program a device |
| send rate-limited read requests | change or link a group address marked `protected = true` |
| edit the project files, each edit saved to the history first | |

Each tier is a flag on `bussard mcp`:

| Flag | Effect |
|---|---|
| `--passive` | the server never transmits on the bus, not even read requests |
| `--allow-writes` | adds group writes: the assistant can switch a light or move a blind |
| `--allow-programming` | adds writing one device's link tables and parameters, after you approve its plan |
| `--no-model-edits` | removes the tools that edit the project |

A server with `--allow-writes` or `--allow-programming` against a gateway that is not on your laptop refuses to start without `--allow-remote-gateway`. A protected group address is refused over MCP with no override at all; only `bussard write --force` on the command line reaches it.

!!! warning
    `--allow-writes` and `--allow-programming` let the assistant transmit on the real bus. Read [Safety](../explanation/safety.md) before you add either.

## A first conversation

The learn loop names a group address one button press at a time. Ask the assistant to help, then press a button you know:

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
            New group address Hallway light, type 1.001.
            Hallway push button now switches Hallway light.
```

`knx_wait_for_telegram` waits for the press, `knx_infer_group` ranks the possible data types from the telegrams it has seen, and `knx_set_group` writes the name you agreed to. Every telegram narrows the candidates, so an uncertain one gets "press it again". The loop only listens and never transmits.

Every edit comes back as a plain sentence for the assistant to quote, and touches the project files only. Nothing reaches a device until it is programmed: on a server started with `--allow-programming` the assistant shows you its plan and writes the device after your yes. [Change what a button does](../how-to/change-a-link.md) walks through that.

## Check what the assistant changed

```text
You:        What did you change in my project?
Assistant:  (calls knx_describe_change)
            One change since the last saved state: Living room blind
            actuator, channel B, now listens to Central down. The actuator
            still needs to be programmed.
You:        And before that?
Assistant:  (calls knx_history)
            Saved states, newest first: the link above at 10:45 today, and
            the import of house.knxproj yesterday at 18:12.
```

`knx_describe_change` lists every change since the last saved state in the same sentences, and `knx_history` lists every saved state with the command that caused it; an edit over MCP shows as `mcp knx_add_link` and similar.

## Undo

```text
You:        Undo that.
Assistant:  (calls knx_undo)
            Living room blind actuator, channel B, no longer listens to
            Central down. Your project is back at the state saved at 10:00;
            the state before this undo is kept as well.
```

Undo restores the project files only. A device you already programmed keeps the change until you program it again. The undo is saved too, so you can undo an undo.

## Next steps

- [The first weekend](first-weekend.md): audit the project, back up every device, make one change.
- [Change what a button does](../how-to/change-a-link.md): plan and apply a link change.
- [MCP tools](../reference/mcp-tools.md): every tool, tier and flag of the server.
- [The assistant as operator](../explanation/assistant.md): why the assistant edits text and you run the physical steps.
