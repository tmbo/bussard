- After `knx_setup` imports a keyring into the key store, the MCP server
  opens its KNXnet/IP Secure tunnel with the keyring's tunnelling users
  right away; before, they took effect only after a server restart (#779).
  The setup summary names the users the tunnel offers, or, when the keyring
  does not open, says the tunnel is plain until the server restarts with
  `BUSSARD_KEYRING_PASSWORD` set.
