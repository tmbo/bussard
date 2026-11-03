- When the operating system refuses bussard access to the local network
  (macOS Local Network privacy, also after a rebuild or update of bussard),
  the bus status, `knx_bus_status` and the bus tools' refusals now say so and
  name the setting to change, instead of `socket error: Broken pipe` or
  `No route to host`. A KNXnet/IP Secure probe that fails with a socket
  error no longer falls back to a plain tunnel, and `knx_bus_status` reports
  no tunnelling user while the bus is down.
