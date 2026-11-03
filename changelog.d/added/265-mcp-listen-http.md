- `bussard mcp --listen [<ADDR>]` serves the MCP tools over the streamable
  HTTP transport at `http://<ADDR>/mcp`, for clients that take a server URL
  (#265). It binds `127.0.0.1:0` by default and prints the URL; the tiers and
  the real-gateway write gate are the same as over stdio. A non-loopback
  address needs `--allow-remote-clients` and a bearer token
  (`BUSSARD_MCP_TOKEN`, or one generated and printed once); `--allow-host`
  admits a reverse proxy's host name. bussard does not terminate TLS: Claude
  Desktop's custom connectors reach it through a proxy or tunnel you run.
