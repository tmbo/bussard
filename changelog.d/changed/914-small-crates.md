- A device management connection runs the tunnel's KNXnet/IP channel code
  (sequenced request and ACK, heartbeat, inbound sequence check, disconnect)
  instead of its own copy; the tunnel is unchanged on the wire. The secure,
  monitor, viz and project crates drop duplicate helpers and dead API; the
  `bussard monitor --json` record keeps its field names (#914).
