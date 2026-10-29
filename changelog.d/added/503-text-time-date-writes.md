- `write`, the MCP `knx_write_group` tool, `viz` and HA automations can send
  text (`16.000` ASCII, `16.001` Latin-1, `28.001` UTF-8), a time (`10.001`,
  `Mon 07:30`), a date (`11.001`, `2026-10-29`) and a date-time (`19.001`,
  `2026-10-29 12:30:00 summer`) (#503). A `16.x` value now decodes the whole
  14 octets and trims only the trailing padding; `monitor` notes a byte above
  7Fh on `16.000` and a `28.001` string without its terminating NUL.
