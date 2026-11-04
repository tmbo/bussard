- `keys enroll` and `keys add-certificate` load the key store afresh for every
  certificate, so a tool key or group key another command or the MCP server
  saved during the session is kept instead of overwritten. `keys enroll`,
  `keys add-certificate` and `interface secure` (CLI and MCP) refuse to save
  the key store when the file changed since they loaded it, with an error
  that says so, rather than overwrite it (#793).
