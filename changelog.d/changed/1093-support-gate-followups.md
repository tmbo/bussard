- The supported-device gate covers more (#1093). Over MCP, a chat app that can
  show the server's questions (elicitation) gets bussard's own question before
  a write to a device not on the list, so the assistant cannot answer for the
  human; `allow_unsupported` counts only without it. `apply` of an IP
  interface's `[knxnet]` table is gated on the CLI and over MCP like every
  other device write. `bussard audit` and `bussard status <address>` print the
  verdict, text and `--json`. `knx_restore_parameters` and
  `knx_restore_tables` keep their digest on an `unsupported_device` refusal,
  as `knx_apply_device` does.
