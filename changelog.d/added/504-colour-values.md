- `write`, the MCP tools and HA automations take a colour: `#RRGGBB` or
  `rgb(r, g, b)` on `232.600`, `#RRGGBBWW`, `#RRGGBB` or `rgbw(r, g, b, w)`
  with `-` for a channel to mark invalid on `251.600` (#504). `read` and
  `monitor` decode `242.600` (x, y, brightness and the validity bits),
  `249.600`, `250.600`, `252.600` and `254.600` instead of showing raw hex.
