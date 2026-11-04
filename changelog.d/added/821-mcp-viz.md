- `knx_viz` opens the `bussard viz` page from chat (#821): the MCP server
  serves the page itself and returns its URL. The page reads the server's
  own project and its one bus connection, so it takes no extra tunnelling
  slot, and it is read-only in every tier, `--passive` included.
  `bussard mcp --viz-listen <ADDR>` fixes its address.
