- knx-sim starts a KNX Data Secure device `activated`: security mode on, the
  tool key, group keys, sender table and group-object flags from the sim
  config or an ETS keyring export (#1054). CI now flashes the synthetic
  Data Secure product secured with the key store, applies a parameter change
  over it, and checks both against golden request streams and between the
  CLI and the MCP server, next to parameter-only goldens for two plain
  products.
