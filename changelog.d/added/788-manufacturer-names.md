- `import` and `import-product` keep the manufacturer list of the ETS master
  data in `products/manufacturers.toml`; `scan`, the other commands and the MCP
  tools name every manufacturer ETS knows, and an id no list knows reads
  `unknown manufacturer (0x0048)` (#788).
