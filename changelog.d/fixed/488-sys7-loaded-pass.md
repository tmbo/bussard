- A System 7 `flash` of a device that already holds an application no longer
  unloads load-state machines 1 to 4 and restarts the device before the
  download, as ETS's application download does neither, whatever the device
  holds; `--parameters-only` and the MCP flash drop that restart too. `flash
  --full` keeps the pass, as ETS runs it only after its own Unload command.
  The offline oracle plans a capture with ETS's Unload with `--full` (#488).
